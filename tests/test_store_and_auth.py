"""The store's failure modes, and the authentication posture's fail-closed rules."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
from pathlib import Path

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from complyops import auth, create_app, records, store
from complyops.audit.journal import read_entries
from complyops.records import RecordError
from complyops.store import StoreError
from complyops.views import refusals

SUITE_KEY = bytes(range(32)).hex()


# ============================ the store ============================


@pytest.mark.parametrize("hostile", ["../escape", "a/b", "", "..", "reg name", "reg.json"])
def test_a_register_name_that_could_escape_the_directory_is_refused(
    tmp_path: Path, hostile: str
) -> None:
    """The name is never caller-supplied, and is validated anyway.

    A name that escaped this directory would write a compliance register over something
    else on the volume, which is not a failure worth discovering later.
    """
    with pytest.raises(StoreError, match="not a usable register name"):
        store.register_path(str(tmp_path), hostile)


def test_a_register_that_is_not_a_list_of_records_is_refused(tmp_path: Path) -> None:
    path = store.register_path(str(tmp_path), "tasks")
    path.parent.mkdir(parents=True)
    path.write_text('{"not": "a list"}', encoding="utf-8")
    with pytest.raises(StoreError, match="not a list of records"):
        store.read(str(tmp_path), "tasks")


def test_a_register_that_is_not_json_is_refused(tmp_path: Path) -> None:
    path = store.register_path(str(tmp_path), "tasks")
    path.parent.mkdir(parents=True)
    path.write_text("not json at all", encoding="utf-8")
    with pytest.raises(StoreError, match="could not be read"):
        store.read(str(tmp_path), "tasks")


def test_an_implausibly_large_register_is_refused_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store, "MAXIMUM_REGISTER_BYTES", 10)
    path = store.register_path(str(tmp_path), "tasks")
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps([{"id": "TSK-0001"}] * 5), encoding="utf-8")
    with pytest.raises(StoreError, match="implausibly large"):
        store.read(str(tmp_path), "tasks")


def test_a_failed_write_leaves_the_previous_register_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Losing a compliance register is worse than refusing a write."""
    store.write(str(tmp_path), "tasks", [{"id": "TSK-0001", "title": "Original"}])

    def explode(self: Path, _target: Path) -> None:
        raise OSError("no space left on device")

    monkeypatch.setattr(Path, "replace", explode)
    with pytest.raises(store.StoreError, match="could not be replaced"):
        store.write(str(tmp_path), "tasks", [{"id": "TSK-0002", "title": "Replacement"}])
    monkeypatch.undo()

    assert store.read(str(tmp_path), "tasks")[0]["title"] == "Original"
    assert not list((tmp_path / store.RECORDS_DIRNAME).glob("*.tmp"))


def test_an_exception_inside_the_block_writes_nothing(tmp_path: Path) -> None:
    """The property that makes a rejected audit entry safe: both happen, or neither does."""
    store.write(str(tmp_path), "tasks", [{"id": "TSK-0001", "title": "Original"}])
    with (
        pytest.raises(RuntimeError, match="the audit entry was refused"),
        store.register(str(tmp_path), "tasks") as rows,
    ):
        rows.append({"id": "TSK-0002", "title": "Should not survive"})
        raise RuntimeError("the audit entry was refused")

    assert [row["id"] for row in store.read(str(tmp_path), "tasks")] == ["TSK-0001"]


def test_a_failure_while_reading_still_releases_the_lock(tmp_path: Path) -> None:
    """A held lock would wedge the register for the life of the process."""
    path = store.register_path(str(tmp_path), "tasks")
    path.parent.mkdir(parents=True)
    path.write_text("not json", encoding="utf-8")

    for _ in range(2):
        with pytest.raises(StoreError), store.register(str(tmp_path), "tasks"):
            pass  # pragma: no cover - the enter raises


def test_concurrent_edits_to_one_register_do_not_lose_a_row(tmp_path: Path) -> None:
    """Two threads editing one register must both survive.

    Without the lock the read-modify-write interleaves and one edit is silently dropped,
    which on a compliance register is a lost record rather than a visible error.
    """
    workers = 16

    def add(index: int) -> None:
        with store.register(str(tmp_path), "tasks") as rows:
            rows.append({"id": f"TSK-{index:04d}", "title": f"Task {index}"})

    threads = [threading.Thread(target=add, args=(index,)) for index in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(store.read(str(tmp_path), "tasks")) == workers


def test_iterating_registers_on_a_volume_with_none_yields_nothing(tmp_path: Path) -> None:
    assert list(store.iter_registers(str(tmp_path))) == []


# ============================ the records boundary ============================


def test_an_unknown_register_is_refused_by_the_record_layer(tmp_path: Path) -> None:
    with pytest.raises(RecordError, match="is not a register"):
        records.read(str(tmp_path), "nope")
    with pytest.raises(RecordError, match="is not a register"):
        records.check_fields({"title": "x"}, register="nope")


def test_identifiers_continue_from_the_highest_in_use() -> None:
    """A deleted row must not let a later record reuse its identifier."""
    rows = [{"id": "TSK-0001"}, {"id": "TSK-0007"}, {"id": "not-an-id"}]
    assert records.next_id(rows, "TSK") == "TSK-0008"
    assert records.next_id([], "INC") == "INC-0001"


def test_an_update_that_changes_nothing_records_no_transition(tmp_path: Path) -> None:
    chain = _chain()
    first = records.mutate(
        data_dir=str(tmp_path),
        chain=chain,
        register="tasks",
        action="TSK_CREATED",
        actor="a@b.uk",
        fields={"title": "Same"},
    )
    again = records.mutate(
        data_dir=str(tmp_path),
        chain=chain,
        register="tasks",
        action="TSK_UPDATED",
        actor="a@b.uk",
        record_id=first["id"],
        fields={"title": "Same"},
    )
    assert again["updated"] == first["updated"], "an unchanged record must not be touched"


def test_an_edit_that_is_not_a_transition_reports_no_states(tmp_path: Path) -> None:
    """A title change is not a state change, and must not claim to be one."""
    chain = _chain()
    created = records.mutate(
        data_dir=str(tmp_path),
        chain=chain,
        register="tasks",
        action="TSK_CREATED",
        actor="a@b.uk",
        fields={"title": "Before"},
    )
    records.mutate(
        data_dir=str(tmp_path),
        chain=chain,
        register="tasks",
        action="TSK_UPDATED",
        actor="a@b.uk",
        record_id=created["id"],
        fields={"title": "After"},
    )
    entry = chain.written[-1]
    assert entry.fields_changed == "title"
    assert entry.old_state == ""
    assert entry.new_state == ""


def test_counts_report_every_state_in_the_vocabulary(tmp_path: Path) -> None:
    chain = _chain()
    records.mutate(
        data_dir=str(tmp_path),
        chain=chain,
        register="risks",
        action="RSK_CREATED",
        actor="a@b.uk",
        fields={"title": "A risk", "state": "AT_RISK"},
    )
    summary = records.counts(str(tmp_path))
    assert summary["risks"]["AT_RISK"] == 1
    assert summary["risks"]["total"] == 1
    assert summary["tasks"]["total"] == 0


def _chain() -> object:
    """Return a real audit chain that also keeps what it wrote."""
    from complyops.audit import AuditChain  # noqa: PLC0415

    class Recording(AuditChain):
        """A chain that remembers its entries, so a test can read them back."""

        written: list[object] = []  # noqa: RUF012 - one per instance, set below

        def append(self, fields: dict[str, str]) -> object:
            """Append and remember."""
            entry = super().append(fields)
            self.written.append(entry)
            return entry

    chain = Recording(None, key=bytes.fromhex(SUITE_KEY), key_id="k1")
    chain.written = []
    return chain


# ============================ the authentication posture ============================


def test_production_without_entra_refuses_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """A build that degrades quietly to "anybody may be anybody" is worse than one that stops."""
    monkeypatch.setenv("COMPLYOPS_ENV", "production")
    monkeypatch.delenv("TENANT_ID", raising=False)
    with pytest.raises(auth.AuthNotConfiguredError, match="Refusing to start"):
        auth.check_startup()


def test_production_without_a_session_key_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ephemeral key differs between workers and signs everybody out on each restart."""
    monkeypatch.setenv("COMPLYOPS_ENV", "production")
    monkeypatch.delenv("SESSION_KEY", raising=False)
    with pytest.raises(auth.AuthNotConfiguredError, match="ephemeral session key"):
        auth.signing_secret()


def test_a_configured_session_key_is_used_verbatim(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SESSION_KEY", "a-configured-session-key-value")
    assert auth.signing_secret() == b"a-configured-session-key-value"


def test_development_generates_an_ephemeral_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SESSION_KEY", raising=False)
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    assert len(auth.signing_secret()) == 32


def test_the_development_banner_disappears_once_entra_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TENANT_ID", raising=False)
    assert "self-asserted" in (auth.development_banner() or "")

    for name in ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "REDIRECT_URI"):
        monkeypatch.setenv(name, "configured")
    assert auth.development_banner() is None
    assert auth.entra_is_configured() is True


@pytest.mark.parametrize(
    ("expected", "received", "matches"),
    [
        ("abc", "abc", True),
        ("abc", "abd", False),
        ("", "abc", False),
        ("abc", None, False),
        (None, None, False),
    ],
)
def test_the_sign_in_state_is_compared_in_constant_time_and_fails_closed(
    expected: str | None, received: str | None, matches: bool
) -> None:
    assert auth.state_matches(expected, received) is matches


@pytest.mark.parametrize(
    ("target", "lands_on"),
    [
        ("/console", "/console"),
        ("/api/registers", "/api/registers"),
        ("//evil.example/", "/console"),
        ("https://evil.example/", "/console"),
        ("", "/console"),
        (None, "/console"),
    ],
)
def test_the_post_sign_in_redirect_cannot_leave_this_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str | None, lands_on: str
) -> None:
    """An open redirect would let a phishing link bounce a signed-in user off this origin."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    app = create_app()
    with app.test_request_context("/sign-in"):
        assert auth.redirect_after_sign_in(target).headers["Location"] == lands_on


def test_an_entra_authorise_url_carries_the_state(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in [
        ("TENANT_ID", "tenant"),
        ("CLIENT_ID", "client"),
        ("CLIENT_SECRET", "secret"),
        ("REDIRECT_URI", "https://comply-ops.apps.bluestaq.com/auth/callback"),
    ]:
        monkeypatch.setenv(name, value)
    verifier = auth.new_verifier()
    url = auth.entra_authorise_url(
        "the-state", challenge=auth.challenge_for(verifier), nonce="the-nonce"
    )
    assert url.startswith("https://login.microsoftonline.com/tenant/")
    assert "state=the-state" in url
    assert "client_id=client" in url
    assert "code_challenge_method=S256" in url
    assert "nonce=the-nonce" in url
    assert "secret" not in url, "the client secret must never reach a URL"
    assert verifier not in url, "the PKCE verifier must never reach a URL"


def test_the_audit_actor_is_marked_when_self_asserted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    app: Flask = create_app()
    with app.test_request_context("/"):
        auth.sign_in("ash.higgins@bluestaq.uk", verified=False)
        assert auth.audit_actor().endswith(auth.SELF_ASSERTED_SUFFIX)
        auth.sign_in("ash.higgins@bluestaq.uk", verified=True)
        assert auth.audit_actor() == "ash.higgins@bluestaq.uk"


def test_an_unusable_signing_key_leaves_the_app_bootable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The diagnostics read-out is the recovery channel, so a bad key must not stop boot.

    Every mutating route then fails closed, because no entry can be written.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    app = create_app()
    assert app.extensions["complyops_chain"] is None
    assert app.test_client().get("/api/diagnostics").status_code == 200


def test_a_mutation_fails_closed_without_an_audit_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A change that cannot be evidenced must not happen.

    503, not 400: the caller's input is fine and the signing key is not, so the honest
    answer is that this end is at fault and retrying later is worth doing.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    client = create_app().test_client()
    client.post(
        "/sign-in",
        data={
            "actor": "ash.higgins@bluestaq.uk",
            "csrf_token": client.get("/").headers["X-CSRF-Token"],
        },
    )
    # Re-read after signing in: `auth.sign_in` clears the session, which is deliberate
    # session-fixation defence, so the pre-sign-in token is no longer this session's.
    token = str(client.get("/api/registers").headers["X-CSRF-Token"])

    refused = client.post(
        "/api/registers/tasks", json={"title": "x"}, headers={"X-CSRF-Token": token}
    )
    assert refused.status_code == 503
    body = refused.get_json()["error"]
    assert "the audit log is unavailable" in body
    assert str(tmp_path) not in body, "no server-side path may reach a client error"
    assert store.read(str(tmp_path), "tasks") == [], "nothing may be stored"


# ============================ staging, and its failures ============================


def test_staging_writes_the_file_before_the_block_ends(tmp_path: Path) -> None:
    """The point of staging: the expensive half happens where a caller can still abort."""
    holder = store.register(str(tmp_path), "tasks")
    with holder as rows:
        rows.append({"id": "TSK-0001", "title": "Access review"})
        holder.stage()
        assert store.read(str(tmp_path), "tasks") == [], "not committed until exit"
        staged = list((Path(tmp_path) / "records").glob(".tasks-*.tmp"))
        assert len(staged) == 1, "the contents are on disk, awaiting a rename"
    assert len(store.read(str(tmp_path), "tasks")) == 1


def test_an_abandoned_block_leaves_no_staged_file(tmp_path: Path) -> None:
    """A refused audit entry must not leave litter beside the register."""
    holder = store.register(str(tmp_path), "tasks")
    with contextlib.suppress(RuntimeError), holder as rows:
        rows.append({"id": "TSK-0001", "title": "Access review"})
        holder.stage()
        raise RuntimeError("the audit entry was refused")

    assert store.read(str(tmp_path), "tasks") == []
    assert list((Path(tmp_path) / "records").glob(".tasks-*.tmp")) == []


def test_staging_twice_leaves_one_file(tmp_path: Path) -> None:
    """A caller that stages again replaces its own staged copy rather than adding one."""
    holder = store.register(str(tmp_path), "tasks")
    with holder as rows:
        rows.append({"id": "TSK-0001", "title": "First"})
        holder.stage()
        rows[0]["title"] = "Second"
        holder.stage()
        assert len(list((Path(tmp_path) / "records").glob(".tasks-*.tmp"))) == 1
    assert store.read(str(tmp_path), "tasks")[0]["title"] == "Second"


def test_a_register_that_cannot_be_prepared_raises_a_store_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every filesystem failure in this module is a StoreError, so callers handle one thing."""

    def refuse(**_kwargs: object) -> tuple[int, str]:
        raise OSError("no space left on device")

    monkeypatch.setattr(store.tempfile, "mkstemp", refuse)
    with pytest.raises(store.StoreError, match="could not be prepared"):
        store.stage(str(tmp_path), "tasks", [{"id": "TSK-0001"}])


def test_a_register_that_cannot_be_written_raises_a_store_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """And the half-written temporary file is removed rather than left beside the register."""
    real = os.fsync

    def refuse(descriptor: int) -> None:
        raise OSError("no space left on device")

    monkeypatch.setattr(os, "fsync", refuse)
    try:
        with pytest.raises(store.StoreError, match="could not be written"):
            store.stage(str(tmp_path), "tasks", [{"id": "TSK-0001"}])
    finally:
        monkeypatch.setattr(os, "fsync", real)

    assert list((Path(tmp_path) / "records").glob(".tasks-*.tmp")) == []


def test_a_full_volume_answers_503_rather_than_an_unhandled_500(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A register that cannot be written is this end's fault, and the body says nothing more."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    monkeypatch.setenv("AUDIT_HMAC_KEY", bytes(range(32)).hex())
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    client = create_app().test_client()
    client.post(
        "/sign-in",
        data={
            "actor": "ash.higgins@bluestaq.uk",
            "csrf_token": client.get("/").headers["X-CSRF-Token"],
        },
    )
    token = {"X-CSRF-Token": client.get("/api/registers").headers["X-CSRF-Token"]}

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise store.StoreError("the 'tasks' register could not be prepared: [Errno 28]")

    monkeypatch.setattr(store, "stage", refuse)
    refused = client.post("/api/registers/tasks", json={"title": "x"}, headers=token)

    assert refused.status_code == 503
    assert refused.get_json()["error"] == "the register is unavailable. See /api/diagnostics."


def test_a_refused_register_write_leaves_the_log_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The staging control, asserted where it actually shows.

    Removing `holder.stage()` from `records.mutate` leaves the status code identical: the
    fallback write in `__exit__` fails just the same and the route still answers 503. What
    changes is the log, which gains an immutable SUCCESS entry for a change the register
    never received. That is the whole point of staging, so it is the thing to assert.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    monkeypatch.setenv("AUDIT_HMAC_KEY", bytes(range(32)).hex())
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    client = create_app().test_client()
    client.post(
        "/sign-in",
        data={
            "actor": "ash.higgins@bluestaq.uk",
            "csrf_token": client.get("/").headers["X-CSRF-Token"],
        },
    )
    token = {"X-CSRF-Token": client.get("/api/registers").headers["X-CSRF-Token"]}
    before = len(read_entries(str(tmp_path)))

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise store.StoreError("the 'tasks' register could not be prepared: [Errno 28]")

    monkeypatch.setattr(store, "stage", refuse)
    refused = client.post("/api/registers/tasks", json={"title": "x"}, headers=token)

    assert refused.status_code == 503
    assert len(read_entries(str(tmp_path))) == before, (
        "no entry may describe a change the register never received"
    )
    assert store.read(str(tmp_path), "tasks") == []


def test_the_container_runs_one_worker(tmp_path: Path) -> None:
    """Four source files and two documentation sections rest correctness on this.

    `chain.py`, `journal.py`, `anchor.py` and `store.py` all state that a second process
    would fork the chain or lose an edit, and the mitigation is that there is no second
    process. Nothing pinned it, so raising the worker count would silently falsify all six.
    """
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(encoding="utf-8")
    assert "--workers 1" in dockerfile
    assert "--workers 2" not in dockerfile


# ============================ the environment is fail-closed ============================


def test_an_unset_environment_is_production(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unset means production, and that direction is the whole point.

    The default was `development`, and the variable appeared in neither the environment
    table nor `.env.example`, so a deploy that followed the documentation exactly ran with
    the Secure cookie flag off, Entra ID unenforced and an ephemeral session key, silently.
    A fail-closed control whose default is "off" is not one.
    """
    monkeypatch.delenv("COMPLYOPS_ENV", raising=False)
    assert auth.is_production() is True


@pytest.mark.parametrize("value", ["", " ", "dev", "DEVELOPMENT ", "prod", "Production", "0"])
def test_only_the_exact_word_selects_development(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """A typo must not silently buy the weaker posture."""
    monkeypatch.setenv("COMPLYOPS_ENV", value)
    assert auth.is_production() is (value.strip().lower() != "development")


def test_an_unset_environment_refuses_to_boot_unconfigured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Loudly, in both directions. A missing variable is never a silent downgrade."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.delenv("COMPLYOPS_ENV", raising=False)
    for name in ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "REDIRECT_URI", "SESSION_KEY"):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(auth.AuthNotConfiguredError, match="COMPLYOPS_ENV is production"):
        create_app()


def test_the_environment_variable_is_documented(monkeypatch: pytest.MonkeyPatch) -> None:
    """It governs three fail-closed controls and was named in neither place.

    A reader following `.env.example` or the deployment table would never learn it exists,
    which is how the guards came to be inert in the documented deploy.
    """
    root = Path(__file__).resolve().parents[1]
    assert "COMPLYOPS_ENV" in (root / ".env.example").read_text(encoding="utf-8")
    assert "COMPLYOPS_ENV" in (root / "docs" / "DEPLOYMENT.md").read_text(encoding="utf-8")


def test_a_hostile_actor_cannot_suppress_the_failed_sign_in_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal path must record nothing the caller chose.

    Passing the raw actor let a caller submit one the audit boundary refuses, a leading
    `=`, `-` or `@`, a non-ASCII character or a double quote, and get a 302 with no entry.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    monkeypatch.setenv("AUDIT_HMAC_KEY", bytes(range(32)).hex())
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    app = create_app()
    client = app.test_client()

    # Short values as well as long ones. Every hostile value was 250 characters, so all of
    # them tripped the length cap and the character-class refusal was never exercised.
    # Exactly the number the collapse records individually. Every other shape is covered
    # one at a time by `test_no_actor_shape_suppresses_its_own_refusal`; carrying a longer
    # tuple here read as coverage that was not happening.
    hostile = ("=ash", "renée", "=" * 250)
    for actor in hostile:
        # A fresh token each time: a hostile actor short enough to pass the length cap
        # reaches `auth.sign_in`, which clears the session, so the previous token is stale.
        client.post(
            "/sign-in",
            data={"actor": actor, "csrf_token": client.get("/").headers["X-CSRF-Token"]},
        )

    entries = app.extensions["complyops_chain"].entries
    assert len(entries) == refusals.RECORDED_PER_WINDOW, "one refusal recorded per attempt"
    assert all(entry.action == "LOGIN_FAILED" for entry in entries)
    assert all(entry.actor == "unknown" for entry in entries), "never the caller's own value"


@pytest.mark.parametrize("actor", ["=ash", "-ash", "@ash", "+ash", "renée", 'a"b', "é" * 250])
def test_no_actor_shape_suppresses_its_own_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, actor: str
) -> None:
    """Each shape on its own, so the character-class branch is exercised, not just the cap."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    monkeypatch.setenv("AUDIT_HMAC_KEY", bytes(range(32)).hex())
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    app = create_app()
    client = app.test_client()

    client.post(
        "/sign-in", data={"actor": actor, "csrf_token": client.get("/").headers["X-CSRF-Token"]}
    )

    entries = app.extensions["complyops_chain"].entries
    assert [entry.action for entry in entries] == ["LOGIN_FAILED"], actor
    assert entries[0].actor == "unknown"
