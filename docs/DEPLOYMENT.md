# comply-ops deployment parameters

First-delivery parameters table for the Bluestaq App Store, per `release-and-deploy`. The operator configures the App Store from this table, so it is the single source of the platform settings. Regenerate it whenever any row changes; a later delivery need only carry the delta.

Every value below is either COPY-PASTE EXACT or explicitly `[delete]`. Nothing here is a descriptive placeholder, because a description near a paste-able field gets pasted as a literal value and the app's fail-closed boot then rejects it.

## Platform settings

| Setting | Value |
|---|---|
| App slug | `comply-ops` (single hyphen; a double hyphen fails the pipeline with zero stages run) |
| Display name | Bluestaq Compliance Operations Console |
| App type | Web App |
| Detected template | `python` (by `requirements.txt` at the package root) |
| Container port | 8080 |
| `PORT` contract | The app reads `PORT` and defaults to 8080, bound to `0.0.0.0`. The Dockerfile sets no `ENV PORT`. Never type `PORT` into the console. |
| Quality gate | Applies. Coverage read from `coverage.xml` (Cobertura), which must be at least 80% with zero open violations. |
| Memory | 1Gi (within the 8Gi envelope) |
| CPU | 1 (within the 6 CPU envelope) |
| Visibility | Owner to confirm. `TBC, re-verify` with Adam Field. |

## Health paths (all must return 200, unauthenticated)

| Path | Kind | Behaviour |
|---|---|---|
| `/` | Router probe | 200 plain text. Never a redirect: the platform router treats a 302 as unhealthy. |
| `/healthz`, `/livez`, `/ping`, `/health` | Liveness | 200, dependency-free, touches nothing. |
| `/readyz` | Readiness | Proves the data directory accepts a real write, racing a 3 second timeout. Returns 503 with the resolved path and the exact errno when it cannot. |
| `/api/diagnostics` | Diagnostics | Booleans, counts, and length BANDS only. Never a secret value, and never an exact length. `AUDIT_HMAC_KEY` additionally reports `usable`, from the same validator the audit chain uses, so a value the console accepted but the application refuses is visible in one read. It does echo `buildId`, `dataDir` and `port`, which are operational rather than secret. |

## Environment variables

The correct console state for a code-defaults app is an EMPTY environment tab for everything the platform injects. The variables below are operator-set because the app cannot obtain them any other way.

| Variable | Source | Value |
|---|---|---|
| `PORT` | Platform-injected | `[delete]` from the console. Set at the pod level. |
| `STORAGE_MOUNT_PATH` | Platform-injected by the FILE_STORAGE add-on | `[delete]` from the console. |
| `TENANT_ID` | Operator-set, not secret | The Bluestaq Ltd Entra ID tenant identifier. |
| `CLIENT_ID` | Operator-set, not secret | The comply-ops application registration identifier. |
| `REDIRECT_URI` | Operator-set, not secret | `https://comply-ops.apps.bluestaq.com/auth/callback` |
| `CLIENT_SECRET` | Operator-set, SECRET | The application registration client secret. See the channel warning below. |
| `SESSION_KEY` | Operator-set, SECRET | The Flask session signing key. |
| `BUILD_ID` | Operator-set, not secret | The deployed commit SHA, surfaced by `/api/diagnostics`. |
| `LOG_VIEW_EVENTS` | Operator-set, not secret | `false` unless the ISM decides otherwise. |
| `AUDIT_HMAC_KEY` | Operator-set, SECRET | The audit signing key. Must be real key material: hexadecimal or base64 decoding to at least 32 bytes, carrying at least 20 distinct byte values, and not printable text. Generate with `openssl rand -hex 32`. A passphrase is refused however it is encoded, because every stored row is a message and its tag and the list is readable by more people than hold the key, so a low-entropy value falls to an offline attack and returns full re-stamping power over the audit log. Without a key no audit entry can be written: the chain fails closed rather than writing an unsigned entry. Used verbatim and never trimmed or unquoted, so do not wrap it in quotes. `/api/diagnostics` reports `usable` for this variable, which is the fastest way to confirm the console value was accepted. |
| `AUDIT_KEY_ID` | Operator-set, not secret | `k1` for the first key. Recorded on every entry it signs and covered by the digest, so it is read verbatim like the key itself: a quoted or padded value is refused rather than trimmed, because a rewritten identifier cannot be reproduced on independent re-verification. |
| `AUDIT_RETIRED_KEYS` | Operator-set, SECRET | Empty until the first rotation. Then `id:key` pairs separated by semicolons, each key held to the same bar as the current one, so entries signed before the rotation stay verifiable. A retired key remains a valid signer for history but cannot sign the END of the log, so a leaked retired key cannot be used to re-sign the whole thing. A malformed value is refused loudly at boot rather than skipped: skipping it silently produced the verdict "chain broken", indistinguishable from real tampering, over evidence nobody had touched. |

## Add-ons

| Add-on | Needed | Why |
|---|---|---|
| FILE_STORAGE | Yes | The server-side session store and the audit anchor must survive a restart. The anchor records where the audit log should end. It is written atomically and durably, authenticated under the signing key so an actor with volume access but no key can neither forge nor alter one, and it will not accept a write that shortens the record. Read the limits below before relying on it. Injects `STORAGE_MOUNT_PATH=/data`. |
| POSTGRESQL | No | Records live in local files on the FILE_STORAGE volume, exported for upload to SharePoint by hand. A database is not needed for the record volumes involved, and adding one would put the system of record somewhere the export cannot reach atomically. |
| REDIS | No | Considered as a session store instead of FILE_STORAGE. `TBC, re-verify` if session contention appears. |
| CLAMAV | No | The app accepts no file uploads in this release. |

## Operations requests

● **`securityContext.fsGroup`.** The container runs as UID 10001, and the FILE_STORAGE volume is root-owned by default, so every write returns `EACCES` until operations set `fsGroup` on the pod. Raise this request before the first deploy, not after `/readyz` returns 503. This is platform-general for every non-root workload using the volume add-on.
● **The single-sign-on gateway.** The platform can place a Keycloak gateway in front of the app, which returns 401 to the browser independently of the app and while the pipeline is fully green. This app performs its own Microsoft Entra ID authentication, so the two collide. Ask the platform team to exempt exactly these paths and nothing else: `/`, `/healthz`, `/livez`, `/ping`, `/health`, `/readyz`. Do NOT ask for a blanket `/api/*` exemption: `/api/diagnostics` reports which credentials arrived and roughly how long they are, and it must move behind the app's own authorisation check when the auth module lands. Diagnostic tell: if `/livez` returns 401, the 401 is the gateway, not the app.

## Secret channel warning

`CLIENT_SECRET`, `SESSION_KEY` and `AUDIT_HMAC_KEY` on an encrypted-secret channel can be delivered stale, delivered by a different mechanism than a plain variable, or be absent altogether. A critical value on that channel with no recovery path has locked an owner out for days.

One mitigation is in place today: `/api/diagnostics` reports each input, including `AUDIT_HMAC_KEY`, as a boolean and a length band, so a stale value and a correct value are distinguishable without leaking either, and no probe failure or configuration value can prevent boot, so that read-out stays reachable however badly the environment is set. The request-time fail-closed behaviour is NOT yet implemented, because no route yet consumes these values; it lands with the authentication module. See the known gaps below.

The audit signing key is the one to place most carefully. It is what makes the audit log evidence rather than a story, and losing it makes existing history unverifiable. `AUDIT_RETIRED_KEYS` exists so a rotation does not orphan history, but there is no recovery from losing every copy of a key. Keep an offline copy in the evidence library alongside the anchor export below.

## Key rotation

Rotation is supported and tested, and the procedure is short.

1. Generate the new key: `openssl rand -hex 32`.
2. Move the current `AUDIT_HMAC_KEY` value and its `AUDIT_KEY_ID` into `AUDIT_RETIRED_KEYS` as one `id:key` pair.
3. Set `AUDIT_HMAC_KEY` to the new value and `AUDIT_KEY_ID` to a new identifier.
4. Save and apply the full environment set, then confirm `/api/diagnostics` reports `usable` true for the key.

No re-anchor step is needed. The anchor authenticates against every key still held, and the anchor records the key that signed the LAST entry rather than the key the application would sign with next, so verification stays green across the rotation and through the first append afterwards. Keep every retired key for as long as the entries it signed are retained: dropping one makes those entries unverifiable, which is reported as a configuration fault rather than as tampering, but it is still unverifiable.

## Rollback

There is no separate rollback on this platform. Roll back by resubmitting the previous package through `resubmit_app`. This is the first release, so no previous package exists yet: state that honestly at the deploy gate rather than claiming a tested rollback. The `deploy-gate` requires a known rollback before an irreversible step.

## Known gaps before the first submission

● The image has not been built or probed. The Docker daemon is unavailable in the build environment, so the non-root user, the port binding, the absence of a package manager, the absence of setuid bits, and the flattened single layer are verified by construction against the Dockerfile, not by running the container. Before the deploy gate, build it and run: `docker run --rm --entrypoint sh comply-ops -c 'command -v apt-get dpkg apt pip pip3; find / -xdev -perm /6000; id'` and expect no command found, no path listed, and `uid=10001`.
● Request-time fail-closed handling of a missing or stale credential is not implemented. Nothing yet consumes `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, `SESSION_KEY` or `REDIRECT_URI` outside the diagnostics read-out. It lands with the authentication module.
● The audit anchor is not yet written by any code path, because no entry is yet persisted. The store and its verification are in place and tested; wiring them to the record write path lands with the records module, and that is also where the in-process append lock has to become an inter-process lock on the storage volume, since the container serves two gunicorn workers.
● Rate limiting is not implemented. When it lands, `/readyz` and `/api/diagnostics` both belong behind the broad limiter. The per-request amplification is already closed: the storage probe is single-flight, so concurrent callers join one probe rather than each starting a thread.
● **What the anchor does not do, stated plainly because it was over-claimed twice.** The anchor is a file on the persistent volume, so an actor who can write that volume can delete it, and can delete anything else placed there to notice the deletion. Two controls were added in successive review rounds to close that: an authentication tag, and a first-use marker so that an absent anchor reads as a tamper alarm rather than a fresh install. The tag holds and is worth having. The marker only raised the cost from one deletion to two, in the same directory, which is no cost at all to an actor who already holds write access to it. It is kept, and it is now authenticated so an unkeyed actor can neither forge nor plant one, but it does not close the attack.

  Against the attacker the threat model actually names, somebody with write access to the stored log but no volume access and no key, the anchor works: an edit, a re-stamp, a reorder, a deletion, a truncation and a wholesale replacement are all caught.

  Against an actor with write access to the volume there are TWO gaps, not one. Deleting the anchor and its marker together leaves a state indistinguishable from a fresh install. And restoring a genuine OLDER anchor alongside a matching truncation of the log, across a restart, is worse: the refusal to move backwards is held in process memory only, restarts are routine on this platform, and the result does not look like a missing anchor. It looks like clean shorter history, and verification positively certifies it as intact. Neither gap needs the signing key.

  What closes both is corroboration against a store the volume attacker does not control. This application holds its records in local files and does not integrate with SharePoint, so that store is the EXPORTED evidence pack: a pack carrying an anchor is a copy held somewhere that actor cannot reach. "The last exported pack records more entries than the volume now accounts for" is the tamper alarm, and "neither holds anything" is the only honest fresh install. That comparison needs the export module AND a written comparison step in the operating rhythm, and neither exists yet, so `read_anchor` returning nothing means only "this volume holds no anchor", never "the log is empty". **Do not treat this control as complete until both exist.** `TBC, re-verify` the design with the ISM.

  Compensating controls in the meantime: restricting write access to the FILE_STORAGE volume as tightly as the platform allows, SharePoint versioning and retention on the exported packs once uploaded, and exporting on a defined cadence so an off-volume copy always exists. See "The export cadence is a security control" below.
● The base image is patched by rebasing to a newer pinned digest, not by `apt-get upgrade` at build time, so the image stays reproducible from its pinned inputs. Check for a newer `python:3.12-slim` digest before each release.
● The platform pipeline simulation has not been run against a package artefact, because no package script exists yet. It must be green before any upload.
● Deployment to the App Store rather than Azure App Service is not yet signed off by the Managing Director.

## AUD-001 and AMD-001 conformance

Where this build satisfies the policy, where it exceeds it, and where it does not. An
assessor reading this table should not have to take anything on trust, so each row says
what to look at.

Both source documents are stored verbatim in `policy/`, so every row can be checked
against the clause it claims rather than against a paraphrase. Note that the approval row
of each is unsigned: Adam Field's date is blank on both. They are treated as binding here,
and that gap is recorded rather than assumed closed.

| Policy requirement | This build | Evidence |
| --- | --- | --- |
| AUD-001, SHA-256 hash over timestamp, user, action, resource | **Exceeded.** HMAC-SHA256 under a server-held key, over the full AUD-001 event field set, chained to the previous entry. Deviation recorded for the Managing Director's sign-off. | `src/complyops/audit/hashing.py`, golden vector in `tests/test_audit_hashing.py` |
| AUD-001, write-once from the application's perspective | **Met by design, not yet implemented.** `AuditChain.append` is the only path that produces an entry and it never updates or deletes, but nothing persists an entry yet, so this is a property of code that does not exist. | `AuditChain.append` |
| AUD-001, event field set | **Met for four categories, deviated for three.** One fixed shape rather than one per category, because a digest over a varying field set cannot be verified without knowing the variant. Authentication, Task management, Register operations and Audit export map onto `FIELD_ORDER` directly. Incident management and Administration are covered by the old-and-new-value deviation below. **Form submissions asks for "key field values" and no field can carry a value**, so that clause is unimplementable under the same decision and is recorded as a deviation in its own right, not covered by the row below. | `FIELD_ORDER`, `policy/AUD-001-audit-controls.md` |
| AUD-001, old and new value of a changed field | **Deviated, deliberately, and the deviation is weaker than first claimed.** Field NAMES only in `fields_changed`, capped at 128 bytes; an enumerated workflow state in `old_state` and `new_state` under a character rule that rejects the common SHAPES of record content (a space, lower case, an `@`, over 32 characters) but does not make it impossible: a single upper-case token such as `HIGGINS` or `SW1A1AA` satisfies it. A closed state vocabulary would be structural and is not yet definable, because the real state set is not knowable until the records module. Caller discipline is load-bearing in the meantime. Ash's decision, recorded for sign-off; the vocabulary is `TBC, re-verify`. | `src/complyops/audit/validation.py` |
| AUD-001, 24-month active retention, annual CSV export, annual pruning | **Met by design, not yet implemented.** The anchor records the archive boundary, the chain carries it across an append, and `verify_log` walks from it, so a pruned active log verifies rather than reading as tampered. The export and prune procedure itself lands with the export module. | `Anchor.after_prune`, `test_the_archive_boundary_survives_a_prune_a_restart_and_an_append` |
| AUD-001, Q-06 quarterly hash verification on a sample | **Mechanism met, procedure open.** `verify_sample` is the sampling entry point and cannot report a truncation, by construction; `verify_log` verifies the whole ACTIVE log and requires the anchor. There is no scheduler, no runbook step, and no caller, so the quarterly activity itself is not yet real. | `src/complyops/audit/chain.py` |
| AUD-001, SharePoint list versioning and ISC-Owners permission as the delete control | **Not in the live path.** The application no longer writes to SharePoint, so this control applies to the exported evidence pack once uploaded, and not before. See the export cadence note below. | This document |
| AUD-001, Monitoring and Alerting (five Application Insights alerts) | **Not applicable as written.** The App Store does not provide Application Insights. `TBC, re-verify`: AUD-001 needs an amendment naming the platform equivalent. The gap is open, not covered. | Adam Field owns the amendment |
| AUD-001, timestamps in UTC (IASME 12.3) | **Met.** RFC 3339 in UTC is the only accepted form; a local offset is rejected at the boundary. | `validation._check_timestamp` |
| AMD-001 10.6, static application security testing on every change | **Met.** `bandit` in the local loop and, as of this round, in Continuous Integration, which is the only leg that runs on every change. `ruff` and `mypy` are a linter and a type checker and do not satisfy this clause. | `scripts/verify.sh`, `.github/workflows/verify.yml` |
| AMD-001 10.6, dependencies pinned with integrity verification | **Met.** Exact pins, hash-locked, installed with `--require-hashes`. | `requirements.txt`, `Dockerfile` |
| AMD-001 10.6, security headers on all responses | **Met.** All four named headers, plus three more, on every response including probes, redirects and error pages, applied OVER anything a route set. The previous implementation was first-writer-wins, so a route could serve a wider policy and keep it; a narrower per-route policy now goes through an explicit `tighten` call and there is no door for a wider one. | `src/complyops/security_headers.py`, `tests/test_security_headers.py` |
| AMD-001 10.6, SECURITY.md linking POL-006 | **Partially met.** The file exists and names POL-006 and the responsible owner, but carries no reporting address or link, so a reporter outside the company cannot actually report. `TBC, re-verify`: the ISM must supply the address; inventing one would breach the no-invention rule. | `SECURITY.md` |
| AMD-001 10.6, secrets never in source, environment variables, or configuration | **Partially deviated.** No secret is in source or in history. Secrets DO arrive as environment variables, because that is the App Store's only injection mechanism; Azure Key Vault is not available on this platform. `TBC, re-verify` the wording with the ISM. | `.env.example`, App Store environment configuration |
| AMD-001 10.6, input validation, output encoding, CSRF tokens | **Not yet.** No request-handling route exists beyond the health and diagnostics paths. Lands with the forms module. | Open |
| AMD-001 10.6, OWASP Top 10 testing before deployment | **Not yet.** Named for the September 2026 penetration test per AMD-001 11.5. | Open |
| AMD-001 10.4, accreditation review before production deployment | **Not yet.** Required before the first deploy, and it is the Managing Director's sign-off. | Open |

## The export cadence is a security control

This needs stating plainly because it is a consequence of the standalone-files decision
that is easy to miss.

The application is the system of record on its own volume. AUD-001 rests its
delete-and-modify control on SharePoint list versioning and ISC-Owners permission, and
with no SharePoint integration that control does not sit in the live path any more. It
applies to the evidence pack once uploaded, and to nothing before.

So between exports, the volume holds the only copy of the audit log and its anchor, and
an actor with write access to that volume can delete both. That is the open blind spot
recorded above, and the export is what closes it: an uploaded pack is a copy held
somewhere that actor does not control, and it carries the anchor, so a later deletion
becomes detectable by comparison.

Two things follow. **Export on a defined cadence, not when convenient**, and record the
cadence in the operating rhythm so a missed export is visible as a missed task rather
than as nothing at all. And **keep the anchor with the pack**, because a pack without it
proves the entries were internally consistent and nothing about whether any were removed.

`TBC, re-verify` the cadence with the ISM. The audit log review rhythm in AUD-001 is
weekly, monthly and quarterly, so a weekly export aligned to task W-01 is the obvious
candidate and is not yet agreed.

## Deferred by design, and why each one cannot be finished here

Five controls in the audit module are deliberately incomplete. Each is blocked on a module
that does not exist yet, and each was attempted inside this slice and produced a worse
result than declaring it. They are listed here so a reviewer can tell a deferral from an
oversight, and so nobody closes one by adding another file to the same volume.

| Control | Why it cannot be finished here | Lands with |
| --- | --- | --- |
| Anchor corroboration against an off-volume store | The anchor lives on the volume, so an actor who can write the volume can delete it and anything placed beside it to notice. Two attempts (an authentication tag, then a first-use marker) raised the cost from one deletion to two in the same directory. Closing it needs a copy the attacker cannot reach, which is the exported evidence pack. | The export module |
| Cross-process append and anchor serialisation | The append lock and the rollback high-water mark are per process, and the container serves two gunicorn workers, so neither is shared between them. Closing it needs an inter-process lock on the storage volume, which needs a write path to hold it. | The records module |
| A closed vocabulary of workflow states | The character rule on `old_state` and `new_state` rejects the common shapes of record content, not record content itself. Making it structural needs the real state set, and the v1 prototype yields only a partial one (`open`, `pending`, `closed`, `done`, `On Track`, `At Risk`, `Planned`). Inventing the rest would breach the no-invention rule. | The records module |
| Spreadsheet safety of the exported pack | The boundary rules exclude the double quote, so a value cannot terminate its own comma-separated field, but the comma itself is legitimate in a user agent and required in `fields_changed`. A safe export must quote every field and prefix any cell starting `=+-@`. There is no exporter to put that in. | The export module |
| AUD-001 Q-06 quarterly verification | `verify_sample` and `verify_log` exist and are tested. There is no scheduler, no runbook step and no caller, so the quarterly activity is a mechanism rather than a practice. | The records module and the operating rhythm |

Two AUD-001 clauses need a policy amendment rather than code, and both are Ash and Adam
Field's to make:

● **Form submissions, "key field values"** (`policy/AUD-001-audit-controls.md`). No field in
  `FIELD_ORDER` can carry a value, by the same decision that keeps old and new values out
  of the log. The clause is unimplementable under that decision. Recorded as a deviation.
● **Monitoring and Alerting**, five Application Insights alerts the App Store does not
  provide. Recorded as not applicable as written.
