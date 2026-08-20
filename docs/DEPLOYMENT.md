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
| `/api/diagnostics` | Diagnostics | Booleans, counts, and length BANDS only. Never a configured value, and never an exact length. |

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
| `AUDIT_HMAC_KEY` | Operator-set, SECRET | The audit signing key, at least 32 characters. Without it no audit entry can be written: the chain fails closed rather than writing an unsigned entry. |
| `AUDIT_KEY_ID` | Operator-set, not secret | `k1` for the first key. Recorded on every entry it signs. |
| `AUDIT_RETIRED_KEYS` | Operator-set, SECRET | Empty until the first rotation. Then `id:key` pairs separated by semicolons, so entries signed before the rotation stay verifiable. |

## Add-ons

| Add-on | Needed | Why |
|---|---|---|
| FILE_STORAGE | Yes | The server-side session store and the audit anchor must survive a restart. The anchor is the trusted record of where the audit log should end, and it is what detects a wholesale rewrite or a truncation of the log; it is written atomically to this volume. Injects `STORAGE_MOUNT_PATH=/data`. |
| POSTGRESQL | No | All records of authority live in SharePoint Lists. |
| REDIS | No | Considered as a session store instead of FILE_STORAGE. `TBC, re-verify` if session contention appears. |
| CLAMAV | No | The app accepts no file uploads in this release. |

## Operations requests

● **`securityContext.fsGroup`.** The container runs as UID 10001, and the FILE_STORAGE volume is root-owned by default, so every write returns `EACCES` until operations set `fsGroup` on the pod. Raise this request before the first deploy, not after `/readyz` returns 503. This is platform-general for every non-root workload using the volume add-on.
● **The single-sign-on gateway.** The platform can place a Keycloak gateway in front of the app, which returns 401 to the browser independently of the app and while the pipeline is fully green. This app performs its own Microsoft Entra ID authentication, so the two collide. Ask the platform team to exempt exactly these paths and nothing else: `/`, `/healthz`, `/livez`, `/ping`, `/health`, `/readyz`. Do NOT ask for a blanket `/api/*` exemption: `/api/diagnostics` reports which credentials arrived and roughly how long they are, and it must move behind the app's own authorisation check when the auth module lands. Diagnostic tell: if `/livez` returns 401, the 401 is the gateway, not the app.

## Secret channel warning

`CLIENT_SECRET`, `SESSION_KEY` and `AUDIT_HMAC_KEY` on an encrypted-secret channel can be delivered stale, delivered by a different mechanism than a plain variable, or be absent altogether. A critical value on that channel with no recovery path has locked an owner out for days.

One mitigation is in place today: `/api/diagnostics` reports each input as a boolean and a length band, so a stale value and a correct value are distinguishable without leaking either, and no probe failure or configuration value can prevent boot, so that read-out stays reachable however badly the environment is set. The request-time fail-closed behaviour is NOT yet implemented, because no route yet consumes these values; it lands with the authentication module. See the known gaps below.

## Rollback

There is no separate rollback on this platform. Roll back by resubmitting the previous package through `resubmit_app`. This is the first release, so no previous package exists yet: state that honestly at the deploy gate rather than claiming a tested rollback. The `deploy-gate` requires a known rollback before an irreversible step.

## Known gaps before the first submission

● The image has not been built or probed. The Docker daemon is unavailable in the build environment, so the non-root user, the port binding, the absence of a package manager, the absence of setuid bits, and the flattened single layer are verified by construction against the Dockerfile, not by running the container. Before the deploy gate, build it and run: `docker run --rm --entrypoint sh comply-ops -c 'command -v apt-get dpkg apt pip pip3; find / -xdev -perm /6000; id'` and expect no command found, no path listed, and `uid=10001`.
● Request-time fail-closed handling of a missing or stale credential is not implemented. Nothing yet consumes `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, `SESSION_KEY`, `SHAREPOINT_SITE_ID` or `REDIRECT_URI` outside the diagnostics read-out. It lands with the authentication module.
● The audit anchor is not yet written by any code path, because no entry is yet persisted. The store and its verification are in place and tested; wiring them to the SharePoint write path lands with the Graph module, and that is also where the cross-process append lock has to become a conditional write against the list.
● Rate limiting is not implemented. When it lands, `/readyz` and `/api/diagnostics` both belong behind the broad limiter.
● The platform pipeline simulation has not been run against a package artefact, because no package script exists yet. It must be green before any upload.
● Deployment to the App Store rather than Azure App Service is not yet signed off by the Managing Director.
