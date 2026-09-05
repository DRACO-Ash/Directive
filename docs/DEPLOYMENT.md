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
| `/readyz` | Readiness | Proves the data directory accepts a real write, racing a 3 second timeout. Returns 503 with the resolved path and the exact errno when it cannot. **Accepted inconsistency:** this route is unauthenticated and gateway-exempt by design, and it publishes `dataDir`, which V2.1 moved behind the authorisation check on `/api/diagnostics`. The platform's readiness probe cannot authenticate, and a readiness failure an operator cannot locate is not a diagnosis, so the path stays. Nothing else joins it: no errno detail beyond an `errno.errorcode` name, no credential map, no audit state. |
| `/api/diagnostics` | Diagnostics | **Accepted unauthenticated disclosure:** the public half returns `version`, `buildId`, `port`, `logViewEvents` and `storageErrno`, which together are a build fingerprint and a volume-state oracle for an anonymous caller. Kept because a platform operator diagnosing a failing pod cannot authenticate to the application, and because `/readyz` already publishes the same errno by necessity. Recorded rather than left to be found. Two halves since V2.1. **Unauthenticated:** `version`, `buildId`, `port`, `storageWritable`, `storageErrno`, `logViewEvents`, `authenticated`. **Signed in only:** `dataDir`, `auditLog` (the state of the audit chain, which names the log's path and its entry count), and `inputs` (which credentials arrived, as booleans and length BANDS, never a value and never an exact length; `AUDIT_HMAC_KEY` additionally reports `usable`, from the same validator the audit chain uses). |

## Environment variables

The correct console state for a code-defaults app is an EMPTY environment tab for everything the platform injects. The variables below are operator-set because the app cannot obtain them any other way.

| Variable | Source | Value |
|---|---|---|
| `PORT` | Platform-injected | `[delete]` from the console. Set at the pod level. |
| `STORAGE_MOUNT_PATH` | Platform-injected by the FILE_STORAGE add-on | `[delete]` from the console. |
| `COMPLYOPS_ENV` | Operator-set, not secret | **Set this to `production`, explicitly.** It governs three fail-closed controls: the `Secure` flag on the session cookie, whether Entra ID is enforced at boot, and whether `SESSION_KEY` is required. `development` selects the local mode; anything else, an unset variable included, is production. It was previously absent from this table while defaulting to `development`, so a deploy following this table exactly ran with all three guards off. The default is now the safe direction, and the row exists so nobody has to rely on it. |
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
● **The single-sign-on gateway.** The platform can place a Keycloak gateway in front of the app, which returns 401 to the browser independently of the app and while the pipeline is fully green. This app performs its own Microsoft Entra ID authentication, so the two collide. Ask the platform team to exempt exactly these paths and nothing else: `/`, `/healthz`, `/livez`, `/ping`, `/health`, `/readyz`. Do NOT ask for a blanket `/api/*` exemption. The credential-presence half of `/api/diagnostics` moved behind the application's own authorisation check in V2.1, so a blanket exemption would now expose only the operational half, but every other `/api/*` route is a register or the audit log and none of them may be exempted. Diagnostic tell: if `/livez` returns 401, the 401 is the gateway, not the app.

## Secret channel warning

`CLIENT_SECRET`, `SESSION_KEY` and `AUDIT_HMAC_KEY` on an encrypted-secret channel can be delivered stale, delivered by a different mechanism than a plain variable, or be absent altogether. A critical value on that channel with no recovery path has locked an owner out for days.

Two mitigations are in place, and the first one has a limit that must be stated because V2.1 introduced it.

`/api/diagnostics` reports each input, including `AUDIT_HMAC_KEY`, as a boolean and a length band, so a stale value and a correct value are distinguishable without leaking either. No probe failure and no configuration value can prevent boot, so the route itself always answers. **But that half of the read-out is now signed-in only, and there is a configuration in which nobody can sign in to reach it.** `entra_is_configured` tests presence, not correctness, so a PRESENT BUT WRONG `CLIENT_SECRET` disables the self-asserted sign-in path while the real one cannot complete. The recovery for that case is NOT this route.

The recovery for that case is the container log, and specifically one line in it. Every boot writes three:

```
boot: inputs TENANT_ID=set(32+), CLIENT_ID=set(32+), AUDIT_HMAC_KEY=MISSING(0), ...
boot: audit log resumed, chain intact across 41 entries
boot: storage accepted a write at /data
```

The first is the one this section rests on, and it is written BEFORE anything that can
refuse to boot, so it survives a refusal. Be precise about the two shapes of failure. A
missing Entra ID variable or a missing `SESSION_KEY` REFUSES TO BOOT, loudly, with a message
naming what to set; the presence map is still written first, and it is what names which of
the four the pod actually received, because the refusal message names all of them. A missing
or wrong `AUDIT_HMAC_KEY`, as illustrated above, boots and serves: the audit path is
unavailable, every register mutation answers 503, and this line is how an operator sees
why. It carries the same presence map as the signed-in half of `/api/diagnostics`, as a boolean and a length band per input, never a value and never an exact length. It is emitted from the application factory rather than from the storage narrative, so a storage probe failure cannot suppress it, and nothing in it can prevent boot. `TBC, re-verify` with the platform team that pod logs are readable from the App Store console without authenticating to the application; that is the assumption this recovery path rests on and it has not been confirmed here.

If an operator cannot sign in: read the pod log, correct the value on the environment channel, and restart. Recorded plainly rather than left to be discovered during an outage.

Request-time fail-closed behaviour IS implemented as of V2.1: the application refuses to boot in production without Entra ID and without `SESSION_KEY`, and every register mutation fails closed without a usable `AUDIT_HMAC_KEY`.

The audit signing key is the one to place most carefully. It is what makes the audit log evidence rather than a story, and losing it makes existing history unverifiable. `AUDIT_RETIRED_KEYS` exists so a rotation does not orphan history, but there is no recovery from losing every copy of a key. Keep an offline copy in the evidence library alongside the anchor export below.

## Key rotation

Rotation is supported and tested, and it costs exactly one extra step.

1. Generate the new key: `openssl rand -hex 32`.
2. Move the outgoing `AUDIT_HMAC_KEY` value and its `AUDIT_KEY_ID` into
   `AUDIT_RETIRED_KEYS` as one `id:key` pair.
3. Set `AUDIT_HMAC_KEY` to the new value and `AUDIT_KEY_ID` to a new identifier.
4. Save and apply the full environment set, then confirm `/api/diagnostics` reports
   `usable` true for the key.
5. **Re-anchor.** First obtain the entries-ever total from OFF this volume: the figure
   recorded by the last exported evidence pack, or your own record. Then run
   `complyops.audit.re_anchor(DATA_DIR, outgoing_key=..., incoming_key=..., expected_total=N)`
   once. It reads the stored anchor under the outgoing key, refuses to proceed if the stored
   total is below `N`, and writes it back under the incoming key, carrying the head, the
   length, the total and the archive boundary unchanged.

Step 5 is not optional and it is not housekeeping. **The anchor authenticates under the
current signing key only**, so until it is re-signed the new key cannot read it and the
audit path fails closed.

`expected_total` is not a formality either, and this is the part to read twice. **Re-anchoring
is the one moment the outgoing key is trusted**, and a rotation is the documented response to
a key that may have leaked, so the outgoing key is precisely the key that may have signed a
forged anchor. An earlier version took its floor from the stored anchor, which is to say from
the volume, which is to say from the attacker: a short forgery planted under the leaked key
was carried forward and certified under the new key by this very step, taking the record from
nine entries to two with no alarm. The off-volume figure is how a number the attacker cannot
reach enters the decision. **After a suspected key compromise, corroborate the stored anchor
against the last exported pack before you re-anchor**, because this step carries forward
whatever the outgoing key certified. See the residual risk above.

That is a deliberate trade, and the reason is worth stating because the opposite choice was
made first and was wrong. Accepting any key still held meant an actor holding a LEAKED
RETIRED key plus write access to the volume could re-sign the whole log under it, write a
matching anchor and marker, and have wholly invented history certified as intact. A key is
retired because it may have leaked, so it is precisely the key the trusted reference must
not accept. Retired keys remain valid for stored ENTRIES, which is what they are for, and
`verify_log` still verifies history across a rotation.

Keep every retired key for as long as the entries it signed are retained. Dropping one
makes those entries unverifiable, which is reported as a configuration fault rather than as
tampering, but unverifiable either way.

## Rollback

There is no separate rollback on this platform. Roll back by resubmitting the previous package through `resubmit_app`. This is the first release, so no previous package exists yet: state that honestly at the deploy gate rather than claiming a tested rollback. The `deploy-gate` requires a known rollback before an irreversible step.

## App Store supply-chain gate readiness

Assessed against the `appstore-python-gate` skill, which is vendored at
`.claude/skills/appstore-python-gate/`. Confidence markers are the skill's and are kept
deliberately: FACT means observed by running it here, INFERENCE means reasoned from that,
UNKNOWN means not established and not to be promoted quietly.

`scripts/preflight.py` from the skill returns **0 blocking, 0 advisory** against this
package. FACT, run at V2.1:

● `pyproject.toml` present with a `[project]` table, which the skill records as the single
  highest-value difference between the packages that clear the gate and the one that failed.
● `requirements.txt` at the root, exactly pinned throughout, every entry hash-carrying.
● No resolver hazards: no git or VCS URL, no `-e .`, no `file:` path, no local reference.
● `Dockerfile` at the package root, every base image digest-pinned.

Three of the standing risks the skill records against its reference application do not apply
here, and one does.

● **The largest gap it names does not exist in this package.** Stage 4 scans
  `requirements.txt` and never reads a separate runtime lockfile, so where the two differ
  the scanned set is not the installed set. This build has no such split: `Dockerfile` line
  22 copies `requirements.txt` and line 23 installs from it under `--require-hashes
  --no-deps`. The file scanned IS the file installed. FACT.
● **The base image is digest-pinned**, not tag-pinned. FACT.
● **There is no fail-open patch step**, because there is no `apt-get upgrade` at all: the
  image takes whatever Debian shipped at the pinned digest and then removes the package
  manager. That trades one failure mode for another and the replacement is real. A pinned
  digest never patches itself, so **this build needs a scheduled rebuild that refreshes the
  digest, rebuilds, re-scans and raises a change if the scan passes.** No such job exists.
  Open, and it is the first thing to add after the first deploy.
● **The final image carries a whole Debian userland.** `FROM scratch` then `COPY --from=prep
  / /` is a layer-flattening device for the image-policy scanner, not a minimal image, so
  Container Scan sees every operating system package rather than only the Python ones. Moving
  to a distroless base would cut the reported count materially without touching application
  code, and it would change the flatten behaviour, so it needs testing rather than adopting
  on trust. INFERENCE, from the skill; not attempted here.

### The SBOM, and exactly what it is

`scripts/verify.sh` now emits `sbom.cdx.json`, a CycloneDX 1.4 document of the runtime tree,
generated by `pip-audit`. No new dependency was added for it: a packaging tool in the build
path is the thing a supply-chain control should add least of.

Two dated reasons to hold our own rather than rely on the platform's. The Dependency Scanning
stage reports an analyser crash and a genuine advisory with the same message, and the presence
of an SBOM artefact is what distinguishes them, so a gate failure can be triaged instead of
guessed at; the skill records four upload cycles spent on that mistake. And the Cyber
Resilience Act's vulnerability reporting duty binds from **11 September 2026**, with a
24-hour early warning from the moment of awareness, which leaves no time to work out by hand
which shipped versions carry a named component.

What it is not, stated plainly rather than left to be assumed. It carries component names,
versions and the dependency graph. It does **not** carry component hashes, licences, or the
generating tool's own identity, so it does **not** meet the CISA 2026 minimum elements
published in July 2026. The hashes exist in `requirements.txt`; merging them in by hand would
make the file less trustworthy rather than more. Closing that needs a real SBOM generator and
a recorded decision to add one. Open.

### Two dates, and what they need from us

● **11 September 2026, fifteen days from this assessment.** CRA vulnerability and incident
  reporting binds, including for products already shipped. It needs a reporting route that
  works and an SBOM current enough to answer "which versions contain this component" inside
  24 hours. `SECURITY.md` still carries no reporting address, which is recorded below as
  partially met against AMD-001 10.6; against this date it stops being a documentation gap
  and becomes an operational one. The address is the ISM's to supply and inventing one would
  breach the no-invention rule. **Ash's decision, and it is now time-bound.**
● **11 December 2027.** Full CRA application, including an SBOM in a commonly used
  machine-readable format covering at least top-level dependencies. The file above is the
  start of that, not the discharge of it.

`TBC, re-verify` whether Bluestaq Ltd is in scope as a manufacturer under the CRA for this
application, and which national CSIRT applies. That is a legal determination, not an
engineering one, and nothing here should be read as having made it.

## Recorded decisions

Settled by the Information Security Manager. Recorded here so they are not re-litigated by
a later reviewer, a gate, or a fresh session.

● **The repository is public, deliberately.** Ash's decision, 4 September 2026. The
  application is not classified. This was raised as a finding on the strength of a sentence
  in `docs/policy/README.md` claiming COMMERCIAL IN CONFIDENCE was "the classification of
  this repository"; that sentence extended the two policy documents' own marking to the
  whole repository, which was never right, and it has been removed. The documents
  themselves are now referenced rather than held (`docs/policy/README.md`). They remain in
  git history, readable at any commit from 20 August 2026; removing them from history would
  need a rewrite and has not been judged necessary.
● **Vulnerability reports go to `dpa@bluestaq.uk`**, under POL-006. Supplied by the ISM,
  4 September 2026. This closes the AMD-001 section 10.6 disclosure-route gap and is the
  route the Cyber Resilience Act reporting duty rests on from 11 September 2026.

## Known gaps before the first submission

● The image has not been built or probed. The Docker daemon is unavailable in the build environment, so the non-root user, the port binding, the absence of a package manager, the absence of setuid bits, and the flattened single layer are verified by construction against the Dockerfile, not by running the container. Before the deploy gate, build it and run: `docker run --rm --entrypoint sh comply-ops -c 'command -v apt-get dpkg apt pip pip3; find / -xdev -perm /6000; id'` and expect no command found, no path listed, and `uid=10001`.
● Entra ID sign-in is implemented and has never run against a real tenant. `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, `SESSION_KEY` and `REDIRECT_URI` are consumed by the authentication module, which refuses to serve a production environment without them and refuses the self-asserted sign-in path whenever a tenant is configured. The full authorisation code flow with Proof Key for Code Exchange is in place and is driven end to end in `tests/test_entra_sign_in.py` against a fake token endpoint, so what is proved is this application's half of the exchange. No request has ever reached Microsoft. `TBC, re-verify` on first deploy: the reply URL registered against the app registration, the tenant's real issuer string, and the wire format of the token response.
● **The identity token's signature is not verified, deliberately, and it needs sign-off.** The token is read only where it arrives in the direct HTTPS response to this application's own back-channel POST carrying its own client secret, which is the case OpenID Connect Core section 3.1.3.7 permits TLS server validation for in place of signature checking. The issuer, audience, expiry and nonce ARE all checked. Adding signature verification means a JSON Web Key Set fetch and an RSA implementation, so a new hash-locked dependency. Recorded as a deviation for Adam Field's sign-off; `claims_from_id_token` must never be called on a token from any other source, and its docstring says so.
● The in-process append lock is still not an inter-process lock on the storage volume. The container runs a single gunicorn worker so that no second process holds a competing view of the chain head, which is a mitigation and not a fix: any other process touching the same volume reopens it. Closed at V2.1: the anchor IS now written on every append, and entries are persisted to `DATA_DIR/audit/log.jsonl` before the call returns.
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

Both source documents are held in the Bluestaq Ltd policy library, not in this repository:
they are internal policy instruments with their own classification and review cycle, and
this application is not classified. `policy/README.md` names them and says how to obtain
the current versions. Each row below cites its clause by reference, so it is read beside
the document rather than against a copy that could go stale here. Note that the approval
row of each is unsigned: Adam Field's date is blank on both. They are treated as binding
here, and that gap is recorded rather than assumed closed.

| Policy requirement | This build | Evidence |
| --- | --- | --- |
| AUD-001, SHA-256 hash over timestamp, user, action, resource | **Exceeded.** HMAC-SHA256 under a server-held key, over the full AUD-001 event field set, chained to the previous entry. Deviation recorded for the Managing Director's sign-off. | `src/complyops/audit/hashing.py`, golden vector in `tests/test_audit_hashing.py` |
| AUD-001, write-once from the application's perspective | **Met by design, not yet implemented.** `AuditChain.append` is the only path that produces an entry and it never updates or deletes, but nothing persists an entry yet, so this is a property of code that does not exist. | `AuditChain.append` |
| AUD-001, event field set | **Met for four categories, deviated for three.** One fixed shape rather than one per category, because a digest over a varying field set cannot be verified without knowing the variant. Authentication, Task management, Register operations and Audit export map onto `FIELD_ORDER` directly. Incident management and Administration are covered by the old-and-new-value deviation below. **Form submissions asks for "key field values" and no field can carry a value**, so that clause is unimplementable under the same decision and is recorded as a deviation in its own right, not covered by the row below. | `FIELD_ORDER`; AUD-001 clause, see `policy/README.md` |
| AUD-001, old and new value of a changed field | **Deviated, deliberately, and the deviation is weaker than first claimed.** Field NAMES only in `fields_changed`, capped at 128 bytes; an enumerated workflow state in `old_state` and `new_state` under a character rule that rejects the common SHAPES of record content (a space, lower case, an `@`, over 32 characters) but does not make it impossible: a single upper-case token such as `HIGGINS` or `SW1A1AA` satisfies it. A closed state vocabulary would be structural and is not yet definable, because the real state set is not knowable until the records module. Caller discipline is load-bearing in the meantime. Ash's decision, recorded for sign-off; the vocabulary is `TBC, re-verify`. | `src/complyops/audit/validation.py` |
| AUD-001, 24-month active retention, annual CSV export, annual pruning | **Met by design, not yet implemented.** The anchor records the archive boundary, the chain carries it across an append, and `verify_log` walks from it, so a pruned active log verifies rather than reading as tampered. The export and prune procedure itself lands with the export module. | `Anchor.after_prune`, `test_the_archive_boundary_survives_a_prune_a_restart_and_an_append` |
| AUD-001, Q-06 quarterly hash verification on a sample | **Mechanism met, procedure open.** `verify_sample` is the sampling entry point and cannot report a truncation, by construction; `verify_log` verifies the whole ACTIVE log and requires the anchor. There is no scheduler, no runbook step, and no caller, so the quarterly activity itself is not yet real. | `src/complyops/audit/chain.py` |
| AUD-001, SharePoint list versioning and ISC-Owners permission as the delete control | **Not in the live path.** The application no longer writes to SharePoint, so this control applies to the exported evidence pack once uploaded, and not before. See the export cadence note below. | This document |
| AUD-001, Monitoring and Alerting (five Application Insights alerts) | **Not applicable as written.** The App Store does not provide Application Insights. `TBC, re-verify`: AUD-001 needs an amendment naming the platform equivalent. The gap is open, not covered. | Adam Field owns the amendment |
| AUD-001, timestamp FORM in UTC | **Met.** RFC 3339 in UTC is the only accepted form, the calendar is parsed rather than pattern-matched, and a local offset is rejected at the boundary. | `validation._check_timestamp` |
| IASME 12.3, time SYNCHRONISATION | **Not met, and not the same clause.** AUD-001 evidences 12.3 as "All timestamps in UTC from Azure App Service (NTP-synchronised)", a platform this build no longer uses. The timestamp is also caller-supplied: nothing in the build generates it or establishes the time source. `TBC, re-verify` the App Store clock source, and consider deriving the timestamp server-side when the records module lands. | Open |
| AMD-001 10.6, static application security testing on every change | **Met.** `bandit` in the local loop and, as of this round, in Continuous Integration, which is the only leg that runs on every change. `ruff` and `mypy` are a linter and a type checker and do not satisfy this clause. | `scripts/verify.sh`, `.github/workflows/verify.yml` |
| AMD-001 10.6, dependencies pinned with integrity verification | **Met.** Exact pins, hash-locked, installed with `--require-hashes`. | `requirements.txt`, `Dockerfile` |
| AMD-001 10.6, security headers on all responses | **Met.** All four named headers, plus three more, on every response including probes, redirects and error pages, applied OVER anything a route set. The previous implementation was first-writer-wins, so a route could serve a wider policy and keep it; a narrower per-route policy now goes through an explicit `tighten` call and there is no door for a wider one. | `src/complyops/security_headers.py`, `tests/test_security_headers.py` |
| AMD-001 10.6, SECURITY.md linking POL-006 | **Met.** The file names POL-006, the responsible owner, and the reporting address `dpa@bluestaq.uk`, supplied by the ISM on 4 September 2026, so a reporter outside the company can actually report. That route is also what the Cyber Resilience Act reporting duty rests on from 11 September 2026. | `SECURITY.md` |
| AMD-001 10.6, secrets never in source, environment variables, or configuration | **Partially deviated.** No secret is in source or in history. Secrets DO arrive as environment variables, because that is the App Store's only injection mechanism; Azure Key Vault is not available on this platform. `TBC, re-verify` the wording with the ISM. | `.env.example`, App Store environment configuration |
| AMD-001 10.6, input validation, output encoding, CSRF tokens | **Met.** Every field is validated at the boundary and rejected rather than coerced (`records.check_fields`, `check_state` against a closed vocabulary). Every untrusted value is escaped by Jinja autoescaping and the API returns JSON, never interpolated HTML. Every state-changing request carries a session-derived token compared in constant time, on the register routes and on sign-in and sign-out alike. | `src/complyops/records.py`, `src/complyops/csrf.py`, `test_a_well_formed_but_wrong_token_is_refused`, `test_a_record_title_is_escaped_in_the_page` |
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

Three of the five controls this table carried at V2.0 are closed by the records, store and
journal modules in V2.1. The two that remain are listed below with what closed the others,
so a reviewer can tell a deferral from an oversight and can see which claims moved.

| Control | State at V2.1 | Where |
| --- | --- | --- |
| Cross-process append and anchor serialisation | **Still open, and now reachable.** The append lock, the register lock and the rollback high-water mark are all per process. V2.0 had no write path, so the gap was theoretical; V2.1 has one, so two processes editing the same register or appending concurrently WOULD lose an edit or fork the chain. The Dockerfile therefore pins `--workers 1 --threads 8` so that no second process exists, which is a mitigation and not a fix: any other process on the same volume, a maintenance script included, reopens it. Closing it needs an inter-process lock on the volume. | `src/complyops/store.py`, `src/complyops/audit/chain.py` |
| An audit entry for a record change that did not land | **Narrowed, not closed.** `records.mutate` stages the register before writing the entry and commits it after, so the serialisation, the disk space and the flush all happen with nothing yet recorded, and only a rename remains. A failure of that rename leaves an immutable entry saying `SUCCESS` for a change the register does not hold. The register is the source of truth for what exists; the log is the account of what was attempted and accepted. Closing it needs a two-phase commit across two files. | `src/complyops/store.py` |
| Rate limiting on the unauthenticated sign-in paths | **Partly closed, and the rest is named here rather than left to be found.** AUD-001 requires a record of every failed authentication, and `/sign-in` and `/auth/callback` are unauthenticated by necessity, so each refusal writes one durable fsynced entry. A bare loop could therefore fill the log toward its 64 MiB refusal cap and leave the audit path unavailable at the next restart, with every register mutation answering 503 until an operator does surgery on the volume. `views/refusals.py` now records the first few refusals per source address per window and collapses the rest into one counted entry, which bounds the single-address case and is better evidence besides. A many-address flood is bounded separately by `GLOBAL_ROWS_PER_WINDOW`, a cap on individual refusal rows across ALL addresses in a window, with the excess counted and written as one entry naming a number of refusals and a number of addresses. **That bound exists because a figure recorded here was wrong.** This row previously stated that the per-address tracker held such a flood to about 4096 entries and 1.66 MiB per window, putting the 64 MiB cap 3.2 hours away. The security gate disproved it by measurement and the measurement was reproduced here: 6000 distinct source addresses inside a single window wrote 6000 durable entries and 2.44 MiB, at 426 bytes each. That is 1.46 times the asserted ceiling, it scales linearly with distinct addresses, and it put the cap about 157,000 addresses away rather than 3.2 hours, which an IPv6 /64 exceeds by twelve orders of magnitude. `MAXIMUM_TRACKED` bounds memory and never bounded rows. The figure was the sizing on which deferring an edge rate limiter rested, so it is corrected rather than quietly dropped, and CLAUDE.md's rule to measure a figure before asserting it is the rule that was broken. The first version of that bound then traded unbounded rows for unbounded memory, which is worse, and the gate caught it in the next round. The set of over-budget addresses had no cap, and the post-budget path does no disk writing, so it is the cheapest request this application serves: measured at 300,000 addresses in one window, 26.1 MiB resident against 0.3 MiB once capped. An unauthenticated caller could have driven the single worker to an out-of-memory restart, and a restart discards every pending count, which is the evidence loss the control exists to prevent. The set is now capped and the address count is reported as a floor (`addresses-atleast-N`) when it hits the cap, because an exact-looking figure that is not exact misleads a reader more than an honest floor.

Three things remain, and the first is a figure rather than a caveat. **At the budget, a sustained flood writes 500 rows and about 208 KiB per five-minute window, so 58.45 MiB a day, and reaches the 64 MiB refusal cap in roughly 1.1 days.** Measured after the fix, on this build. That is the number to size the edge rate limiter against, and it is stated because the in-process collapser bounds the RATE and cannot bound the TOTAL: only a limiter at the edge or log rotation does that. Past the budget, per-address attribution is deliberately traded for the bound. And there is still no timer or shutdown flush, so a count pending when the process is KILLED is lost.

Recorded plainly because the figure in this row has now been wrong twice: first asserted without measurement, then understated by 33 per cent because the collapse and flood summaries were not charged against the cap they were supposed to sit under. Both are corrected, and the rule that was broken both times is CLAUDE.md's requirement to measure a figure before asserting it. The bound is also only as good as `remote_addr`: if the platform ingress presents its own address rather than the client's, every caller shares one bucket. `TBC, re-verify` with the platform team. | `src/complyops/views/refusals.py` |
| Spreadsheet safety of the exported pack | **Still open, and narrowed.** The pack `/api/export` produces is JSON, so no cell is interpreted as a formula and the risk does not arise for it. AUD-001's annual export to Library 08 is specified as CSV, and a CSV exporter must quote every field and prefix any cell starting `=+-@`. There is still no CSV exporter. | `src/complyops/views/api.py` |

Closed since V2.0, each with the test that holds it closed:

● **A closed vocabulary of workflow states.** `records.check_state` holds every transition
  to an enumerated set per register, so no route in this application can put record content
  in `old_state` or `new_state`. Precisely: the audit boundary itself still accepts any
  token satisfying its character rule, so this is a property of the live path rather than
  of the audit module, and a future caller reaching `AuditChain.append` directly is still
  on caller discipline. `test_the_boundary_rejects_bad_input`.
● **Anchor corroboration against an off-volume store, in mechanism.** `/api/export` emits
  the registers, the entries and the anchor as one pack, which is the copy an actor with
  volume write access cannot reach. The practice is not closed: nothing enforces that a
  pack is ever downloaded, and the written comparison step in the operating rhythm does not
  exist. `test_the_export_carries_the_registers_the_entries_and_the_anchor`.
● **The anchor's blind spot, in one direction.** `journal.resume` refuses to start when the
  volume holds entries and no anchor, so a deleted anchor is now detectable at boot. A
  volume holding NEITHER is still indistinguishable from a fresh install without the last
  exported pack. `test_entries_with_no_anchor_refuse_to_resume`.
● **AUD-001 Q-06 quarterly verification, in mechanism.** `/api/audit/verify` runs
  `verify_log` against the live anchor and the console has a control for it. There is still
  no scheduler and no runbook step, so the quarterly activity remains a mechanism rather
  than a practice.

New in V2.1 and worth a reviewer's attention:

● **The log is persistent.** Entries are appended to `DATA_DIR/audit/log.jsonl` and fsynced
  before the write returns, and the anchor is advanced after each one. At V2.0 the entries
  lived in memory and nothing wrote the anchor, so a restart lost the log and started a
  fresh chain with no alarm. AUD-001's 24-month retention was not met by any part of V2.0.
● **The write order is journal, then anchor.** A crash between them leaves the log one
  entry longer than the anchor, which `resume` repairs, and only for entries that chain
  cleanly under the CURRENT key. The reverse order would leave an anchor ahead of its log,
  which is indistinguishable from a truncation.
● **A failure to persist wedges the chain for the life of the process.** The head has
  already advanced in memory, so continuing would fork the log. Every later mutation then
  answers 503. Restarting the pod clears it once the volume fault is fixed.

Two AUD-001 clauses need a policy amendment rather than code, and both are Ash and Adam
Field's to make:

● **The `unrecordable` marker is forgeable.** A source address or user agent the audit
  boundary refuses is recorded as `unrecordable` rather than discarded, because a caller
  must never be able to suppress their own audit entry by choosing a header. That marker is
  itself a legal user agent, so a caller who sends it verbatim is indistinguishable in the
  log from one whose value was refused. Closing that needs a separate field, which means
  changing `FIELD_ORDER`, which breaks every historical digest and is the Managing
  Director's sign-off. The ambiguity is far smaller than losing the entry, so it is
  accepted. Recorded here rather than left in a docstring.
● **Form submissions, "key field values"** (AUD-001, see `policy/README.md`). No field in
  `FIELD_ORDER` can carry a value, by the same decision that keeps old and new values out
  of the log. The clause is unimplementable under that decision. Recorded as a deviation.
● **Monitoring and Alerting**, five Application Insights alerts the App Store does not
  provide. Recorded as not applicable as written.
