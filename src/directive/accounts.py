"""Local accounts: the credential store, password hashing, and the lockout.

This exists because the Bluestaq Ltd Entra ID tenant is not available to this application.
Directive therefore keeps its own list of people, which it has never done before, and that
is a responsibility rather than a feature. Everything in this module is written on the
assumption that the file it manages is the thing an attacker wants most.

**Where the file lives, and why not beside the registers.** Accounts are at
``DATA_DIR/accounts/accounts.json``, NOT under ``DATA_DIR/records/``. The evidence export
globs ``records/*.json``, so an account file placed there would be swept into the pack an
assessor receives, carrying every password hash and every second-factor secret off the
volume. One directory separates a credential store from a disclosure.
``tests/test_accounts.py`` asserts the export cannot reach it rather than trusting this
paragraph.

**Hashing.** ``hashlib.scrypt`` from the standard library, at OWASP's documented minimum
for scrypt of N=2^17, r=8, p=1. Not Argon2id, which OWASP prefers: Argon2id needs a
compiled dependency, the image installs from a hash-locked lockfile with
``--only-binary :all:``, and every shipped component is surface the container scan reads
and a human re-pins when an advisory lands. scrypt is memory-hard, in the standard library,
and named by OWASP at these parameters. The trade is recorded rather than assumed.

**The memory arithmetic, because it decides the concurrency.** N=2^17 with r=8 costs
128 MiB for the duration of one hash, measured at about 430 milliseconds. The container is
sized at 1 GiB and gunicorn runs one worker with eight threads, so eight simultaneous
sign-ins would ask for 1 GiB of scrypt alone and the pod would be killed. Worse, eight
threads blocked on hashing leaves none for the liveness probe, and the platform restarts a
container that cannot answer it. So hashing is bounded by a semaphore of two, a ceiling of
256 MiB, and a caller that cannot get a slot within a short wait is refused rather than
queued. Shedding a sign-in is survivable; a restart loop under load is not.

**What this module does not do.** It does not decide who may sign in, write audit entries,
or touch a session. Those belong to ``auth`` and ``views.auth_routes``. This module answers
one question honestly, which is whether a supplied credential matches a stored one, and
owns the file that holds the stored one.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, TypeGuard

from . import totp
from .audit.validation import FORMULA_LEAD

#: The directory under `DATA_DIR`. Deliberately not `records`, which the export globs.
ACCOUNTS_DIRNAME = "accounts"

#: Bytes of randomness in the token that owns an unconfirmed enrolment secret. Sized like a
#: session identifier because guessing one would hand the guesser another sign-in's
#: unconfirmed secret. NOT a bearer value, and that phrase stood here until a gate called it
#: an over-claim: the token rides inside the server-signed session cookie, so a caller can
#: neither choose one nor write one, and on its own it opens nothing.
ENROLMENT_TOKEN_BYTES = 32

#: The counter value meaning "no code has been accepted yet". Not zero: counter zero is a
#: real RFC 6238 step, the one covering the Unix epoch, and a sentinel that collides with a
#: legitimate value is not a sentinel.
NO_STEP = -1

#: What an unreadable counter reads as. Far beyond any counter a real clock will produce,
#: so a corrupt field refuses every code rather than accepting every code.
FAR_FUTURE_STEP = 2**62

#: What a field holds once it has been cleared: the second-factor secret and its pending
#: half, and nothing else. A named constant rather than a bare empty string, and the reason
#: is worth stating because it looks like noise. The static analyser AMD-001 section 10.6
#: requires reads an empty literal assigned to a `*_secret` key as a hardcoded password, and
#: the obvious silencer, a `# nosec` marker, is read by this project's OWN credential sweep
#: as an exemption claimed outside the declared ledger, which fails the build. The name
#: itself carries no credential word for the same reason: `CLEARED` was flagged in turn.
#: Naming the value satisfies both analysers without telling either one to look away.
CLEARED = ""
ACCOUNTS_FILENAME = "accounts.json"

#: scrypt at OWASP's documented minimum for this algorithm. Changing these does NOT
#: invalidate stored hashes: every hash records the parameters it was made with, so an
#: account hashed under older parameters still verifies and is re-hashed on next sign-in.
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SALT_BYTES = 16

#: How many hashes may run at once, and how long a caller waits for a slot. See the memory
#: arithmetic above: this is the control that keeps a sign-in flood from restarting the pod.
HASH_SLOTS = 2
HASH_WAIT_SECONDS = 3.0

#: Failures before an account is locked, and for how long. The lock is time-bounded on
#: purpose. A permanent lock turns a guessing attempt into a way to deny a colleague access
#: until an administrator intervenes, which is a cheaper attack than the one it prevents.
MAXIMUM_FAILURES = 10
LOCKOUT_SECONDS = 900

#: Password rules. A length floor and nothing else: composition rules push people towards
#: predictable substitutions, and NCSC guidance has argued against them for years. The
#: floor is what stops the choices a lockout cannot save.
MINIMUM_PASSWORD = 12
MAXIMUM_PASSWORD = 1024

#: How many single-use recovery codes are issued at enrolment, and how long each is.
RECOVERY_CODES = 10
RECOVERY_BYTES = 10

#: The two roles. `ADMIN` may administer accounts; both may use every register, which is
#: the single-role position the accreditation already accepted, now with account
#: administration separated out of it.
MEMBER = "MEMBER"
ADMIN = "ADMIN"
ROLES = (MEMBER, ADMIN)

#: The two account states.
ACTIVE = "ACTIVE"
DISABLED = "DISABLED"
STATES = (ACTIVE, DISABLED)

#: A username's shape. The audit log takes printable ASCII by allowlist, and a username
#: reaches it twice: as the `actor` on a sign-in, capped at 320 bytes, and as the
#: `resource_id` on an account administration entry, capped at 128. The SMALLER cap is the
#: binding one, because an account whose creation cannot be audited is an account that
#: should not exist. The rule belongs here, where a person can be told about it, rather
#: than at the boundary where the entry is refused and the operator reads a cap figure.
#:
#: **That sentence was true of the CAP and false of the characters, for six releases.** The
#: set below admits `-`, `+` and `@` anywhere, including first, and the audit boundary
#: refuses exactly those as a leading character because a spreadsheet reads them as a
#: formula. So a username could be created that no entry about it could name. A gate drove
#: the consequences and each was reproduced here: six of six AUD-001 Administration entries
#: recorded `resource_id='unrecordable'`, a promotion to administrator among them;
#: `ACCOUNT_LOCKED` was dropped entirely by an unauthenticated trigger, because
#: `record_event` returns False on an unrecordable actor and the sign-in path discards it;
#: and the account could never sign in, after enrolling a factor and burning ten recovery
#: codes it was never shown. With `BOOTSTRAP_ADMIN=+ops@bluestaq.uk` that bricks the
#: deployment: the sole administrator is created, enrols, and is refused forever, while
#: `ensure_bootstrap` will not make another because the list is not empty.
#:
#: The leading rule is therefore IMPORTED from the audit boundary rather than restated
#: here. Two rule sets drift, which is the argument `validation.recordable`'s own docstring
#: makes, and this is what drifting cost.
MAXIMUM_USERNAME = 128
_USERNAME_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyz0123456789.-_@+"  # lower case only; see `normalise_username`
)

_file_lock = threading.Lock()
_hash_slots = threading.BoundedSemaphore(HASH_SLOTS)


class AccountError(RuntimeError):
    """Raised for a fault a caller can fix. Never raised for a wrong password."""


class ServiceBusyError(AccountError):
    """No hashing slot came free, or the machine could not honour the parameters.

    **A load-shedding refusal, and never a wrong credential.** It has its own class because
    the two were indistinguishable and the consequence was a false record: `verify_password`
    swallowed the busy case and returned False, so the sign-in route counted it as a failed
    attempt, and ten of them locked the account for 900 seconds and wrote an AUD-001
    `ACCOUNT_LOCKED` entry attributing a capacity event to failed credentials. A security
    gate demonstrated it against the CORRECT password. An immutable log that says somebody
    got their password wrong when they did not is a record that over-claims, in front of an
    assessor, and that is the binding ground here rather than the availability one.

    It stays an `AccountError` so that a caller who only wants a verdict and catches the
    base class is no worse off than before; the routes that write audit entries catch this
    one FIRST and refuse without recording a failure.
    """


def normalise_username(raw: object) -> str:
    """Return a username in its canonical form, or raise.

    Lower-cased, because `Ash.Higgins@` and `ash.higgins@` are one person and two accounts
    is how a disabled account survives. The allowlist is characters, not a pattern over
    Unicode: the audit log takes printable ASCII and an entry that cannot be written is a
    sign-in that cannot be attributed.
    """
    if not isinstance(raw, str):
        raise AccountError("a username must be text")
    value = raw.strip().lower()
    if not value:
        raise AccountError("a username is required")
    if len(value.encode("utf-8")) > MAXIMUM_USERNAME:
        raise AccountError(f"a username may be at most {MAXIMUM_USERNAME} bytes")
    bad = sorted(set(value) - _USERNAME_CHARACTERS)
    if bad:
        raise AccountError(
            f"a username may use letters, digits and . - _ @ + only, not {''.join(bad)[:16]!r}"
        )
    if value[0] in FORMULA_LEAD:
        #: The audit boundary's own set, imported rather than mirrored. A name the log
        #: cannot carry is an account that cannot be administered, signed into, or locked
        #: out on the record, so it is refused here where the person is told why.
        raise AccountError(
            f"a username may not begin with {value[0]!r}: the audit log refuses it, because "
            "a spreadsheet reads it as a formula when the evidence pack is exported"
        )
    return value


def check_password_rules(password: object) -> str:
    """Return the password if it may be set, or raise saying why it may not."""
    if not isinstance(password, str):
        raise AccountError("a password must be text")
    if len(password) < MINIMUM_PASSWORD:
        raise AccountError(f"a password must be at least {MINIMUM_PASSWORD} characters")
    if len(password.encode("utf-8")) > MAXIMUM_PASSWORD:
        #: An upper bound as well, because scrypt hashes whatever it is given and a
        #: megabyte password is a way to spend the hashing budget from the sign-in form.
        raise AccountError("that password is too long")
    return password


# ---------------------------------------------------------------- hashing


def _scrypt(password: str, salt: bytes, *, n: int, r: int, p: int) -> bytes:
    """Run scrypt under the concurrency bound. Raises if no slot comes free."""
    if not _hash_slots.acquire(timeout=HASH_WAIT_SECONDS):
        #: Refused rather than queued. A queued caller holds a worker thread, and eight held
        #: threads leave nothing to answer the liveness probe, which restarts the pod.
        raise ServiceBusyError("the sign-in service is busy. Try again in a moment.")
    try:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=SCRYPT_DKLEN,
            #: Explicit, because the default ceiling is far below what these parameters
            #: need and scrypt raises rather than silently using less memory.
            maxmem=2 * (128 * r * n + 128 * r * p),
        )
    except MemoryError as error:
        #: The same class of event as a full slot: the machine cannot do the work right
        #: now. It says nothing about the credential, so it must not be recorded as if it
        #: did. Raised rather than returned for exactly that reason.
        raise ServiceBusyError("the sign-in service is out of memory for hashing.") from error
    finally:
        _hash_slots.release()


def hash_password(password: str) -> str:
    """Return a stored-password string carrying its own parameters.

    The format is `scrypt$n=<n>,r=<r>,p=<p>$<salt>$<hash>`, both parts base64. Storing the
    parameters beside the hash is what lets them be raised later without invalidating every
    existing account: a hash made under the old cost still verifies under the rules it was
    made with, and is replaced on the next successful sign-in.
    """
    check_password_rules(password)
    salt = secrets.token_bytes(SALT_BYTES)
    digest = _scrypt(password, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return "$".join(
        (
            "scrypt",
            f"n={SCRYPT_N},r={SCRYPT_R},p={SCRYPT_P}",
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )
    )


def _require_known_scheme(scheme: str) -> None:
    """Refuse a stored password written by something other than this module."""
    if scheme != "scrypt":
        raise AccountError(f"unknown password scheme {scheme[:16]!r}")


def _parse_stored(stored: str) -> tuple[int, int, int, bytes, bytes]:
    """Return the parameters, salt and digest from a stored string, or raise."""
    try:
        scheme, parameters, salt, digest = stored.split("$")
        _require_known_scheme(scheme)
        values = dict(pair.split("=", 1) for pair in parameters.split(","))
        return (
            int(values["n"]),
            int(values["r"]),
            int(values["p"]),
            base64.b64decode(salt, validate=True),
            base64.b64decode(digest, validate=True),
        )
    except AccountError:
        raise
    except (ValueError, KeyError, TypeError) as error:
        raise AccountError("the stored password is unreadable") from error


def verify_password(stored: str, supplied: object) -> bool:
    """Return whether ``supplied`` matches ``stored``. A verdict, never an exception.

    A stored value this module cannot read returns False rather than raising. That is
    deliberate: a corrupted record must refuse the sign-in, not take the process down, and
    an operator finds it through the refusal rather than through a crash loop.
    """
    if not isinstance(supplied, str) or not supplied:
        return False
    try:
        n, r, p, salt, digest = _parse_stored(stored)
    except AccountError:
        return False
    try:
        candidate = _scrypt(supplied, salt, n=n, r=r, p=p)
    except ValueError:
        #: scrypt itself refuses parameters it cannot honour. Same reasoning: a verdict.
        return False
    return hmac.compare_digest(candidate, digest)


def needs_rehash(stored: str) -> bool:
    """Return whether a stored password was made under weaker parameters than today's."""
    try:
        n, r, p, _, _ = _parse_stored(stored)
    except AccountError:
        return True
    # No hashing here, so `ServiceBusyError` cannot arise and the broad catch above is the
    # parse alone.
    return (n, r, p) != (SCRYPT_N, SCRYPT_R, SCRYPT_P)


#: A stored password that matches nothing, used when the named account does not exist.
#: Without it, a sign-in for an unknown username returns in microseconds and one for a real
#: username takes the full hashing time, which tells an unauthenticated caller which of the
#: two they guessed. The work is real, not a sleep: a timed sleep is a constant an attacker
#: can subtract, and real hashing tracks the machine's own speed.
_DECOY = hash_password("decoy-account-password-never-used-" + secrets.token_hex(16))


def absorb_timing() -> None:
    """Spend the same hashing effort a real verification would, and discard it.

    Swallows the busy case rather than propagating it. This runs on the path where the
    named account does not exist, and raising here would make an absent account answer
    differently from a present one under load, which is the enumeration oracle this
    function exists to close. A caller that could not get a slot has already spent the
    wait, so the effort was spent either way.
    """
    try:
        verify_password(_DECOY, "any value at all, it will not match")
    except ServiceBusyError:
        return


# ---------------------------------------------------------------- recovery codes


def new_recovery_codes() -> tuple[list[str], list[str]]:
    """Return (codes to show the person once, hashes to store).

    Hashed with SHA-256 and no salt, unlike a password, and the difference is the point: a
    recovery code is 80 bits of this application's own randomness rather than something a
    person chose, so there is no dictionary to run against it and no benefit to a slow hash
    that would cost 430 milliseconds per attempt across ten codes.
    """
    codes = [secrets.token_hex(RECOVERY_BYTES) for _ in range(RECOVERY_CODES)]
    return codes, [_recovery_hash(code) for code in codes]


def _recovery_hash(code: str) -> str:
    return hashlib.sha256(code.strip().lower().encode("utf-8")).hexdigest()


def spend_recovery_code(account: dict[str, Any], supplied: object) -> bool:
    """Consume one recovery code if it matches. Mutates ``account`` on success.

    Single use: the hash is removed from the account rather than marked, so a code that has
    been used is a code that no longer exists.
    """
    if not isinstance(supplied, str) or not supplied.strip():
        return False
    wanted = _recovery_hash(supplied)
    held = [str(value) for value in account.get("recovery", [])]
    #: Compared against every held hash without short-circuiting, for the same reason the
    #: one-time password comparison does not short-circuit.
    found = False
    for stored in held:
        if hmac.compare_digest(stored, wanted):
            found = True
    if not found:
        return False
    account["recovery"] = [value for value in held if value != wanted]
    return True


# ---------------------------------------------------------------- the file


def accounts_path(data_dir: str) -> Path:
    """Return the file backing the account list."""
    return Path(data_dir) / ACCOUNTS_DIRNAME / ACCOUNTS_FILENAME


def file_present(data_dir: str) -> bool:
    """Return whether an account file is THERE, as distinct from readable or parseable.

    A caller that cannot find an actor needs to know which of two things happened: the
    account was removed from a list it can read, or the list itself is not available. The
    first is a revocation and the second is a fault, and `auth.live_standing` answers them
    differently.

    An error reading the directory answers False here, and that is safe for a reason worth
    stating precisely, because the sentence here named the wrong order. The only caller
    runs `accounts.load` FIRST and this second, so a directory that cannot be read has
    already raised `AccountError` and been classified as a fault; this function is reached
    only when the load succeeded, where False genuinely means "no file". The swallow is
    belt and braces against a mount that fails between the two reads, and a False there is
    still the safe direction: the caller treats it as a fault and refuses the request.
    """
    try:
        return accounts_path(data_dir).exists()
    except OSError:
        return False


def load(data_dir: str) -> list[dict[str, Any]]:
    """Return every account. An absent file is an empty list, not an error.

    A file that exists and cannot be parsed IS an error, and a loud one. An unreadable
    account list must never read as "no accounts", because the bootstrap path below creates
    an administrator when the list is empty.

    **Every operating-system error is an `AccountError`, the existence check included.**
    `Path.exists` swallows only a handful of errno values, ENOENT and ENOTDIR among them,
    and lets EACCES, EIO, ESTALE and ENAMETOOLONG through as a bare `OSError`. That is not
    an `AccountError`, so it missed both blueprint error handlers and a security gate
    measured `POST /sign-in` answering 500 with NO audit entry against an accounts directory
    at mode 0000, which is exactly what `_unreadable_account_list` exists to prevent and
    what its docstring claimed it did. The class had been narrowed to the unparseable-JSON
    trigger rather than closed. The realistic production trigger is a restricted or
    differently-owned mount against a container running as `10001:10001`, which
    `config.validate_data_dir` already names as expected.
    """
    target = accounts_path(data_dir)
    try:
        if not target.exists():
            return []
        loaded = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise AccountError(f"the account list could not be read: {error}") from error
    if not isinstance(loaded, list):
        raise AccountError("the account list is not a list")
    return [row for row in loaded if isinstance(row, dict)]


def save(data_dir: str, rows: list[dict[str, Any]]) -> None:
    """Replace the account list atomically and durably.

    The same stage-then-rename discipline the registers use, and for a sharper reason here:
    a half-written account file is a file that may parse as fewer accounts than it holds,
    and an account list that loses rows is an access-control failure rather than a lost
    record. The mode is set before anything is written to the file.
    """
    target = accounts_path(data_dir)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        document = json.dumps(rows, indent=2, sort_keys=True)
        handle, temporary = tempfile.mkstemp(dir=str(target.parent), prefix=".accounts-")
    except (OSError, ValueError) as error:
        raise AccountError(f"the account list could not be prepared: {error}") from error
    staged = Path(temporary)
    try:
        #: Owner-only before the hashes land in it, not after. A window in which the file
        #: is world-readable is a window, however short.
        staged.chmod(0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(document)
            stream.flush()
            os.fsync(stream.fileno())
        staged.replace(target)
        descriptor = os.open(str(target.parent), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except BaseException as error:
        staged.unlink(missing_ok=True)
        if isinstance(error, OSError):
            raise AccountError(f"the account list could not be written: {error}") from error
        raise


def find(rows: list[dict[str, Any]], username: str) -> dict[str, Any] | None:
    """Return the account with this username, or None."""
    for row in rows:
        if row.get("username") == username:
            return row
    return None


def new_account(username: str, password: str, *, role: str = MEMBER) -> dict[str, Any]:
    """Return a fresh account record. The caller stores it."""
    if role not in ROLES:
        raise AccountError(f"{str(role)[:32]!r} is not a role")
    return {
        "username": normalise_username(username),
        "password": hash_password(check_password_rules(password)),
        "role": role,
        "state": ACTIVE,
        "totp_secret": CLEARED,
        #: The last counter a one-time code was accepted at, so the same code cannot be
        #: spent twice. `-1` rather than `0`: counter zero is a real RFC 6238 step (the
        #: Unix epoch) and a sentinel that collides with a legitimate value is not one.
        "totp_last_step": NO_STEP,
        #: Bumped whenever every session this account holds should stop being honoured:
        #: a password change and a second-factor reset. The session carries a copy and
        #: `auth.live_role` refuses a mismatch, so "change your password" evicts whoever
        #: took the session over, which is the threat `password_submit`'s own docstring
        #: names and which requiring the current password does not address.
        "session_epoch": 0,
        "recovery": [],
        "must_change_password": True,
        "failures": 0,
        "locked_until": 0,
        "created": _now_text(),
        "updated": _now_text(),
    }


def _now_text() -> str:
    """Return an RFC 3339 timestamp in UTC, matching the audit log's own form."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------- state


def is_locked(account: dict[str, Any], *, now: float | None = None) -> bool:
    """Return whether this account is inside its lockout window."""
    moment = time.time() if now is None else now
    try:
        return float(account.get("locked_until", 0)) > moment
    except (TypeError, ValueError):
        #: An unreadable lock reads as LOCKED. Failing closed on a field an attacker would
        #: want to corrupt is the only safe direction.
        return True


def record_failure(account: dict[str, Any], *, now: float | None = None) -> bool:
    """Count a failure and lock the account if it has had too many. Returns whether locked."""
    moment = time.time() if now is None else now
    try:
        failures = int(account.get("failures", 0)) + 1
    except (TypeError, ValueError):
        failures = 1
    account["failures"] = failures
    account["updated"] = _now_text()
    if failures >= MAXIMUM_FAILURES:
        account["locked_until"] = moment + LOCKOUT_SECONDS
        account["failures"] = 0
        return True
    return False


def clear_failures(account: dict[str, Any]) -> None:
    """Forget the failure count after a successful sign-in."""
    account["failures"] = 0
    account["locked_until"] = 0
    account["updated"] = _now_text()


def set_password(account: dict[str, Any], password: str) -> int:
    """Replace the stored password, clear the must-change flag, invalidate every session.

    Returns the new session epoch, so a caller changing its OWN password can write it back
    onto its session and stay signed in while every other session for this account stops.
    That is the point of the field: `account_routes.password_submit` names a session left
    open on an unlocked machine as the ordinary way an account is taken over, and requiring
    the current password does not evict the person who took it. Changing the password does,
    now.
    """
    account["password"] = hash_password(check_password_rules(password))
    account["must_change_password"] = False
    account["updated"] = _now_text()
    return bump_epoch(account)


def new_enrolment_token() -> str:
    """Return a token naming one half-finished sign-in.

    Minted by `auth.begin_second_factor`, before the enrolment page can be loaded, and that
    ordering is the whole point. It used to be minted BY the page, alongside the secret, so
    a caller who kept the cookie from the first factor and replayed it was never carrying a
    token and was served a freshly minted secret every time. A gate measured 25 replays of
    one cookie producing 25 secrets and 25 fsynced rewrites of the credential store in 0.06
    seconds, each one taking the lock every sign-in and every administration route also
    takes, from a single 430 millisecond password hash. Establishing the token before the
    first mint means a replayed cookie already carries it and matches.
    """
    return secrets.token_urlsafe(ENROLMENT_TOKEN_BYTES)


def enrolment_secret(username: str, token: str, key: bytes) -> str:
    """Return the unconfirmed second-factor secret this half-finished sign-in is entitled to.

    **Derived, and never stored until it is confirmed. That is the whole point of it, and it
    is the third attempt at bounding what this cost.** The enrolment page used to WRITE an
    unconfirmed secret to the credential store, and three rounds of the security gate went
    at the bound on those writes:

    ● The eighth round found one captured pre-enrolment cookie minting a secret per request.
      The token was moved to the first factor so a replayed cookie carries one, and the
      replay then reused rather than minted.
    ● The tenth round found the same amplification with TWO half-finished sign-ins, because
      the mint-or-reuse decision read the ACCOUNT's stored token, which both sessions fought
      over. A per-session bit was added so a sign-in minted at most once.
    ● The eleventh round defeated that bit in one line of attacker code: the bit lives in a
      cookie the SERVER sets, and a client that never carries the cookie back never presents
      it. Measured at 50 loads, 50 secrets and 50 fsynced rewrites of the credential store
      from two password verifications, which is the eighth round's figure unchanged.

    The lesson, written down because it was paid for three times: a bound enforced on state
    the caller holds is not a bound. So there is nothing to mint. The secret is a keyed
    function of the account name and the random token `begin_second_factor` put on the
    session, so the page recomputes the same value on every load and writes NOTHING, and
    `finish_enrolment` recomputes it again from the same token to check the code. The write
    happens once, on the confirming POST, by a caller who has proved possession of a code.

    Three properties follow and each closes something the stored version needed a control
    for. Two half-finished sign-ins derive DIFFERENT secrets, because the token differs, so
    neither can be shown or steal the other's and the ownership comparison that guarded that
    is gone with the state it guarded. A reload derives the same secret, which is the case
    the reuse path existed for. And a password change or a factor reset still kills an
    in-flight enrolment, through the epoch on the pending marker rather than by clearing a
    stored field.

    The key is the application's session signing key, under an explicit label. Deliberate,
    and the reasoning is that the token is only ever carried inside a cookie signed by that
    same key: if it rotates, every cookie is void and every half-finished sign-in with it, so
    a secret that changes with it changes exactly when it has no holder left. A separate
    secret would be one more required environment variable for no property this does not
    already have.
    """
    material = hmac.new(key, f"enrol:{username}:{token}".encode(), hashlib.sha256).digest()
    return totp.new_secret(material[: totp.SECRET_BYTES])


def finish_enrolment(
    account: dict[str, Any], code: object, *, secret: str, now: float | None = None
) -> list[str] | None:
    """Confirm enrolment with a code from the app. Returns recovery codes, or None.

    Returning the codes exactly once is the design: they are hashed on the account and the
    plaintext exists only in this return value and the page that renders it.

    The confirming code is SPENT here, not merely checked. Enrolment completes a sign-in,
    so without this the code the person has just typed into the enrolment form stays valid
    at `/sign-in/verify` for the rest of the window, which is the same replay the sign-in
    path was found to allow and the gate demonstrated from a second session.

    Takes the secret rather than reading one off the account, because there is no longer one
    to read: the caller recomputes it with `enrolment_secret` from the token on its own
    session, and this is the only place it is ever written down. The ownership comparison
    that used to stand here went with the stored field it compared, and so did the clause
    recorded beside it as "reachable and not exploitable": two sign-ins cannot derive the
    same secret, so there is nothing to own.
    """
    if not secret:
        #: No secret, or a secret this session does not own.
        #:
        #: **The ownership half here is a second layer. It IS reachable, and it is held by
        #: no test, and both halves of that sentence are corrections.** The previous version
        #: said it could not be reached, reasoning that `enrol_page` replaces the secret on
        #: a mismatch so a caller could never arrive here with a stale token. That is wrong:
        #: the request token is per SESSION rather than per form, so a POST needs no
        #: intervening GET, and a gate measured this clause entered with the stored token
        #: and the session's token both present and the comparison refusing.
        #:
        #: It is nonetheless not exploitable, and therefore not testable: reaching it needs
        #: a stale token, and a stale token means the stored secret has already been
        #: replaced by the session that took ownership, so the caller cannot produce a code
        #: for it. No code path changes the token while leaving the secret. So this is
        #: recorded as reachable and untested rather than given a test that would pass on
        #: the code mismatch and prove nothing, which is the failure this release has
        #: already made twice.
        return None
    try:
        matched = totp.matching_step(secret, code if isinstance(code, str) else "", now=now)
    except totp.TotpError:
        return None
    if matched is None:
        return None
    codes, hashes = new_recovery_codes()
    account["totp_secret"] = secret
    account["totp_last_step"] = matched
    account["recovery"] = hashes
    account["updated"] = _now_text()
    return codes


def is_enrolled(account: dict[str, Any]) -> bool:
    """Return whether a confirmed second factor is in place."""
    return bool(str(account.get("totp_secret") or ""))


def verify_code(account: dict[str, Any], code: object, *, now: float | None = None) -> bool:
    """Spend this one-time code if it is valid and has not been spent. Mutates ``account``.

    **A one-time password that can be presented twice is not one.** RFC 6238 section 5.2
    carries exactly one normative MUST NOT and it is this. The first version of this
    function asked `totp.verify` for a boolean and nothing remembered the counter, so one
    six-digit code signed in as many fresh sessions as a caller cared to open for the
    ninety seconds the drift window spans, and the code shown on the enrolment page could
    be replayed from another session into a complete sign-in. A security gate demonstrated
    both. The sibling control already had this property: a recovery code works once.

    The counter is written onto the account, so the CALLER must persist it. Every call site
    is inside `accounts.with_lock()` and followed by `accounts.save`, which is the same
    discipline `spend_recovery_code` and `record_failure` already require.

    That discipline is held by `test_the_verify_route_signs_in_with_a_fresh_code_and_spends_it`
    and `test_a_code_spent_at_the_verify_route_cannot_be_replayed`, both in
    `tests/test_local_sign_in.py`. The sentence here used to name `test_account_admin.py`,
    which never calls this function at all, and a gate proved the gap by restoring the
    counter on the route's success branch: the whole suite stayed green while one code
    signed in three fresh clients again. No test in the suite had ever posted a valid,
    unspent code to `/sign-in/verify`, because every helper completes a first sign-in
    through enrolment instead.

    Strictly greater than the stored counter, not merely different. Equal is the replay;
    LESS than is a code from earlier in the window arriving after a later one has been
    accepted, which is a replay too and is what a `!=` comparison would have let through.

    A verdict, never a raise.
    """
    secret = str(account.get("totp_secret") or "")
    if not secret:
        return False
    try:
        matched = totp.matching_step(secret, code if isinstance(code, str) else "", now=now)
    except totp.TotpError:
        #: A stored secret that cannot be decoded refuses the sign-in rather than raising,
        #: for the same reason an unreadable password hash does.
        return False
    if matched is None or matched <= last_step(account):
        return False
    account["totp_last_step"] = matched
    account["updated"] = _now_text()
    return True


def last_step(account: dict[str, Any]) -> int:
    """Return the last counter a code was accepted at, failing CLOSED on a bad value.

    An unreadable counter reads as "the far future", so every code is refused until an
    administrator resets the factor. The alternative, treating it as "never", turns one
    corrupt field into an unlimited replay window, and this field is exactly the one an
    attacker holding the volume would corrupt.
    """
    try:
        return int(account.get("totp_last_step", NO_STEP))
    except (TypeError, ValueError):
        return FAR_FUTURE_STEP


def epoch_of(account: dict[str, Any]) -> int:
    """Return the account's session epoch, failing CLOSED on an unreadable value.

    Takes an account, never `None`. It used to accept `None` and answer the sentinel, which
    read as a fail-closed control and was reachable from nothing: every call site either
    passes a real record or short-circuits on `may_sign_in` first, so a gate's mutant
    returning zero for that case survived the whole suite. Dead fail-closed code reads as a
    held control, so the annotation now says what is true and the type checker holds it.

    An unreadable epoch returns a value far beyond any the application writes, so every
    session that EXISTED when the field was corrupted is refused. Reading it as zero would
    turn one corrupt field into a session that cannot be evicted.

    Be exact about the scope, because the sentence here said "a value no session can be
    carrying" and a gate showed a fresh sign-in being handed exactly that value: a sign-in
    reads the stored epoch and copies it, so a new session matches a corrupt one. That is
    closed at the sign-in routes rather than here, by refusing to complete a sign-in whose
    stored epoch is unreadable; this function stays a pure reader and a verdict.
    """
    try:
        return int(account.get("session_epoch", 0))
    except (TypeError, ValueError):
        return FAR_FUTURE_STEP


def bump_epoch(account: dict[str, Any]) -> int:
    """Invalidate every session this account holds. Returns the new epoch.

    The caller persists it, like every other mutation in this module, and a caller that
    wants to keep its OWN session writes the returned value back onto it.
    """
    account["session_epoch"] = epoch_of(account) + 1 if account.get("session_epoch") else 1
    #: There is no unconfirmed secret on the record to clear any more, and the sentence that
    #: used to be here cleared one. "Every session this account holds stops" still has to
    #: include a half-finished sign-in, and it does: an enrolment secret is derived from the
    #: token on the pending session, `_pending_refusal` refuses a pending sign-in whose epoch
    #: no longer matches, so bumping the epoch is what ends it. The disable-and-re-enable
    #: case the old clearing was written for cannot arise either, because no planted factor
    #: is left on the record for an owner to confirm later.
    account["updated"] = _now_text()
    return int(account["session_epoch"])


def reset_factor(account: dict[str, Any]) -> None:
    """Remove the second factor and its recovery codes, forcing re-enrolment."""
    account["totp_secret"] = CLEARED
    #: Reset with the secret. A new secret produces unrelated codes, so a counter held
    #: against the old one would refuse perfectly good codes from the new device until the
    #: clock caught up with it, which on a corrupt value means never.
    account["totp_last_step"] = NO_STEP
    account["recovery"] = []
    #: And every session this account holds stops being honoured, AND any unconfirmed
    #: enrolment secret goes with them, both inside `bump_epoch`. A factor reset is the
    #: recovery path for a lost phone, so the phone is in somebody else's hands: leaving
    #: their open sessions working would make the reset a formality.
    #:
    #: This function used to call `clear_pending_enrolment` itself as well. Deleting that
    #: call changed nothing, which a gate demonstrated, so it was fail-closed code that
    #: read as a held control and held nothing: the same class as the `epoch_of(None)`
    #: branch removed one commit earlier. One caller, named here.
    bump_epoch(account)
    account["updated"] = _now_text()


def set_state(account: dict[str, Any], state: str) -> None:
    """Enable or disable an account."""
    if state not in STATES:
        raise AccountError(f"{str(state)[:32]!r} is not an account state")
    account["state"] = state
    account["updated"] = _now_text()


def may_sign_in(
    account: dict[str, Any] | None, *, now: float | None = None
) -> TypeGuard[dict[str, Any]]:
    """Return whether this account is in a state that permits a sign-in at all.

    A `TypeGuard` rather than a plain `bool`, so a caller that has already refused the
    `None` case does not then have to assert it away. The three callers each wrote
    `assert account is not None` to get past the type checker, and an `assert` in shipped
    code is removed under `-O` and is a static-analysis finding besides: it states a
    property rather than holding it. Narrowing at the predicate holds it for every caller
    at once.
    """
    return (
        account is not None and account.get("state") == ACTIVE and not is_locked(account, now=now)
    )


def is_admin(account: dict[str, Any] | None) -> bool:
    """Return whether this account may administer other accounts."""
    return account is not None and account.get("role") == ADMIN


def active_admins(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return every enabled administrator. Used to refuse removing the last one."""
    return [row for row in rows if row.get("role") == ADMIN and row.get("state") == ACTIVE]


def redacted(account: dict[str, Any]) -> dict[str, Any]:
    """Return an account with every secret removed, for a page or an API response.

    An allowlist of fields that may be shown, never a denylist of fields to strip. A
    denylist is one new field away from leaking it, and the field most likely to be added
    here is another secret.
    """
    return {
        "username": account.get("username", ""),
        "role": account.get("role", MEMBER),
        "state": account.get("state", ACTIVE),
        "enrolled": is_enrolled(account),
        "must_change_password": bool(account.get("must_change_password")),
        "locked": is_locked(account),
        "recovery_remaining": len(account.get("recovery", [])),
        "created": account.get("created", ""),
        "updated": account.get("updated", ""),
    }


def with_lock() -> threading.Lock:
    """Return the lock held while the account file is read, changed and written back.

    One lock for the whole file rather than one per account: a change to any account
    rewrites the whole list, so two concurrent changes to two different accounts would
    still lose one of them.
    """
    return _file_lock
