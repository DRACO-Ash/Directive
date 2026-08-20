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
| `SHAREPOINT_SITE_ID` | Operator-set, not secret | The `uk-infosec-compliance` site identifier. |
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
| POSTGRESQL | No | All records of authority live in SharePoint Lists. |
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
● Request-time fail-closed handling of a missing or stale credential is not implemented. Nothing yet consumes `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, `SESSION_KEY`, `SHAREPOINT_SITE_ID` or `REDIRECT_URI` outside the diagnostics read-out. It lands with the authentication module.
● The audit anchor is not yet written by any code path, because no entry is yet persisted. The store and its verification are in place and tested; wiring them to the SharePoint write path lands with the Graph module, and that is also where the cross-process append lock has to become a conditional write against the list.
● Rate limiting is not implemented. When it lands, `/readyz` and `/api/diagnostics` both belong behind the broad limiter. The per-request amplification is already closed: the storage probe is single-flight, so concurrent callers join one probe rather than each starting a thread.
● **What the anchor does not do, stated plainly because it was over-claimed twice.** The anchor is a file on the persistent volume, so an actor who can write that volume can delete it, and can delete anything else placed there to notice the deletion. Two controls were added in successive review rounds to close that: an authentication tag, and a first-use marker so that an absent anchor reads as a tamper alarm rather than a fresh install. The tag holds and is worth having. The marker only raised the cost from one deletion to two, in the same directory, which is no cost at all to an actor who already holds write access to it. It is kept, and it is now authenticated so an unkeyed actor can neither forge nor plant one, but it does not close the attack.

  Against the attacker the threat model actually names, somebody with item-edit rights on the SharePoint list but no volume access and no key, the anchor works: an edit, a re-stamp, a reorder, a deletion, a truncation and a wholesale replacement are all caught.

  Against an actor with write access to the volume, deleting both files leaves a state indistinguishable from a fresh install. What closes that is corroboration against a store the volume attacker does not control. In this application that is the list itself: "the list holds audit rows but the volume holds no anchor" is the tamper alarm, and "neither holds anything" is the only honest fresh install. That comparison needs the Graph read path, so it lands with that module, and `read_anchor` returning nothing means only "this volume holds no anchor", never "the log is empty". **Do not treat this control as complete until that corroboration exists.** `TBC, re-verify` the design with the ISM.

  Compensating controls in the meantime: SharePoint list versioning and retention on the list itself, restricting write access to the FILE_STORAGE volume as tightly as the platform allows, and the operator exporting the anchor into the evidence library on a schedule so an offline copy exists.
● The base image is patched by rebasing to a newer pinned digest, not by `apt-get upgrade` at build time, so the image stays reproducible from its pinned inputs. Check for a newer `python:3.12-slim` digest before each release.
● The platform pipeline simulation has not been run against a package artefact, because no package script exists yet. It must be green before any upload.
● Deployment to the App Store rather than Azure App Service is not yet signed off by the Managing Director.
