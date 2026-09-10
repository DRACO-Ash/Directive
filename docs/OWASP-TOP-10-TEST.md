# OWASP Top 10 test record, V2.1

Bluestaq Ltd, Compliance Operations Console (`comply-ops`). Required by AMD-001 section 10.6: "applications are tested against the OWASP Top 10 before production deployment and annually thereafter". This is the pre-deployment test. The annual external test is AMD-001 11.5, first cycle September 2026, and is separate.

| Item | Value |
| --- | --- |
| Commit tested | `ec75bd2` (main, security gate PASS at round twelve) |
| Date | 2026-09-10 |
| Tester | Claude Code session, for Ash Higgins (ISM and DPL) |
| Method | Attacks over the application's HTTP surface using the Flask test client, in development mode and in Entra-configured production mode, plus the verification loop for A06. Script retained in the session scratchpad; every row below is a request that was sent and a response that was observed. |
| Result | 82 checks, 82 passed, 0 failed. Two observations and two gaps recorded below; none is a failure of a control that exists. |

## Scope and limits

● In-process over the WSGI interface, not against a deployed instance. Everything the platform adds or terminates is out of scope here: TLS, the ingress, the real `remote_addr`. Each is named in its category with what to do after the first deploy.
● Not a penetration test. It is a control-by-control check that each OWASP category has a specific defence and that the defence refuses the obvious attack. The September external test is where an adversary spends days on it.
● A row marked passed means the observed response matched the expectation stated in the row, nothing more.

## A01:2021 Broken Access Control

Every mutating and every reading API route is behind `auth.required`; every mutating route also needs the cross-site request forgery (CSRF) token, compared in constant time and failing closed on a non-ASCII value. Register and record identifiers that do not exist are refused with 400, and the response body is generic. The `next` parameter after sign-in is constrained to a same-site path and refuses protocol-relative, backslash and scheme forms.

**Observation, not a failure.** The application has one role. Any authenticated actor can read and write every register and read the audit log. Least privilege is therefore enforced by WHO can authenticate, which is the Entra ID app registration's user assignment, not by the application. That is adequate for a single-team console operated by the ISM and recorded here so it is not mistaken for role-based access control. User assignment is required on the enterprise application, confirmed by the ISM on 2026-09-10; that assignment list is the access list.

| Test | Expected | Observed | Result |
| --- | --- | --- | --- |
| unauthenticated GET /console | 401/403 or redirect to sign-in | `302 /sign-in?next=/console` | Passed |
| unauthenticated GET /api/registers | 401/403 or redirect to sign-in | `401 ` | Passed |
| unauthenticated GET /api/registers/tasks | 401/403 or redirect to sign-in | `401 ` | Passed |
| unauthenticated POST /api/registers/tasks | 401/403 or redirect to sign-in | `401 ` | Passed |
| unauthenticated PATCH /api/registers/tasks/TSK-0001 | 401/403 or redirect to sign-in | `401 ` | Passed |
| unauthenticated GET /api/audit | 401/403 or redirect to sign-in | `401 ` | Passed |
| unauthenticated POST /api/audit/verify | 401/403 or redirect to sign-in | `401 ` | Passed |
| unauthenticated GET /api/export | 401/403 or redirect to sign-in | `401 ` | Passed |
| register name traversal or pollution: '../../etc/passwd' | 400 or 404, never 200 or 500 | `404` | Passed |
| register name traversal or pollution: 'tasks%2F..%2F..' | 400 or 404, never 200 or 500 | `404` | Passed |
| register name traversal or pollution: 'TASKS' | 400 or 404, never 200 or 500 | `400` | Passed |
| register name traversal or pollution: 'tasks;drop' | 400 or 404, never 200 or 500 | `400` | Passed |
| register name traversal or pollution: '__proto__' | 400 or 404, never 200 or 500 | `400` | Passed |
| register name traversal or pollution: 'constructor' | 400 or 404, never 200 or 500 | `400` | Passed |
| PATCH non-existent record id | 400 or 404, never 200 or 500 | `400` | Passed |
| authenticated create with CSRF token | 201/200 | `201` | Passed |
| cross-register id reference (task id via incidents) | 400 or 404, never 200 or 500 | `400` | Passed |
| open redirect next='//evil.example' | redirect stays on-site | `/console` | Passed |
| open redirect next='https://evil.example' | redirect stays on-site | `/console` | Passed |
| open redirect next='/\\evil.example' | redirect stays on-site | `/console` | Passed |
| open redirect next='javascript:alert(1)' | redirect stays on-site | `/console` | Passed |
| open redirect next='\\\\evil.example' | redirect stays on-site | `/console` | Passed |
| authenticated POST without CSRF token | 403 | `403` | Passed |
| authenticated POST with wrong CSRF token | 403 | `403` | Passed |
| CSRF token non-ASCII (compare_digest TypeError path) | 403, no 500 | `403` | Passed |

## A02:2021 Cryptographic Failures

Session cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` in production mode; a tampered cookie payload is rejected. Audit entries are HMAC-SHA256 under a server-held key with a keyed anchor (see A08). Strict-Transport-Security is on every response with `includeSubDomains; preload`.

**Not tested here.** Transport Layer Security is terminated by the App Store ingress, outside this process. The protocol and cipher floor (AMD-001 10.4 asks for TLS 1.2 or above) must be verified against `comply-ops.apps.bluestaq.com` after the first deploy, with `testssl.sh` or `nmap --script ssl-enum-ciphers`, and the result attached to the accreditation record.

| Test | Expected | Observed | Result |
| --- | --- | --- | --- |
| session cookie HttpOnly | HttpOnly present | `complyops_session=eyJjb21wbHlvcHNfYWN0b3IiOiJ0IiwiY29tcGx5b3BzX3ZlcmlmaWVkIjpmYWxzZSwiX...` | Passed |
| session cookie SameSite | SameSite=Lax | `complyops_session=eyJjb21wbHlvcHNfYWN0b3IiOiJ0IiwiY29tcGx5b3BzX3ZlcmlmaWVkIjpmYWxzZSwiX...` | Passed |
| session cookie Secure in development mode | absent (HTTP dev), present in production below | `complyops_session=eyJjb21wbHlvcHNfYWN0b3IiOiJ0IiwiY29tcGx5b3BzX3ZlcmlmaWVkIjpmYWxzZSwiX...` | Passed |
| tampered session cookie payload | not authenticated | `401` | Passed |
| HSTS header on every response | Strict-Transport-Security present | `max-age=31536000; includeSubDomains; preload` | Passed |
| session cookie Secure in production mode (set on the sign-in redirect) | Secure; HttpOnly; SameSite=Lax | `complyops_session=.eJxtjsFSgzAUAP8lZ5mRii16LIVgW0ciKUO5ZEJJEcsjgWAi7fjv1rO97HF3L-ggQbWT...` | Passed |

## A03:2021 Injection

No SQL, no shell, no template string construction: registers are JSON on the volume, read and written through `store.py`. The `state` field is validated against a closed vocabulary (`records.check_state`); every other register field is validated against a closed set of field NAMES and a length cap (`records.check_fields`) and then whitespace-stripped, which is a coercion, so the values themselves are free text. The three server-owned fields `id`, `created` and `updated` are a third case again: a caller who submits them has them discarded rather than rejected, so a client cannot set a record's identity or timestamps. An unknown field, a wrong type, a non-object body, and an invalid JSON body are all 400. Stated this precisely because the summary of this row over-claimed it once, in a signed record, and the correction has to reach the evidence and not only the summary. A stored `<script>` title is rendered escaped by Jinja autoescape. Audit fields are printable ASCII by allowlist, so a User-Agent carrying CRLF, U+2028 or U+202E is substituted with `unrecordable` rather than written to the log, which defeats log-line forgery.

| Test | Expected | Observed | Result |
| --- | --- | --- | --- |
| stored XSS via record title rendered in console | escaped or not rendered raw | `raw present=False, status 201` | Passed |
| JSON responses carry application/json | application/json | `application/json` | Passed |
| X-Content-Type-Options | nosniff | `nosniff` | Passed |
| malformed or out-of-vocabulary field '{"title": "x", "state": "OPEN\'; DROP TAB' | 400/413, never 500 | `400` | Passed |
| malformed or out-of-vocabulary field '{"title": "x", "state": "open"}' | 400/413, never 500 | `400` | Passed |
| malformed or out-of-vocabulary field '{"title": "x", "state": "OPEN "}' | 400/413, never 500 | `400` | Passed |
| malformed or out-of-vocabulary field '{"title": "x", "unknown": "field"}' | 400/413, never 500 | `400` | Passed |
| malformed or out-of-vocabulary field '{"title": 1}' | 400/413, never 500 | `400` | Passed |
| malformed or out-of-vocabulary field '["not", "an", "object"]' | 400/413, never 500 | `400` | Passed |
| malformed or out-of-vocabulary field '{"title": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx' | 400/413, never 500 | `400` | Passed |
| invalid JSON body | 400, never 500 | `400` | Passed |
| log injection via User-Agent (CRLF, U+2028, U+202E) | substituted with 'unrecordable', never stored raw | `unrecordable` | Passed |
| audit field allowlist is printable ASCII | no control or format characters in any stored field | `checked via entry` | Passed |

## A04:2021 Insecure Design

Request bodies over 256 KiB are refused with 413. Unauthenticated refusals are collapsed per address and bounded globally at 500 rows per five-minute window, so a flood cannot fill the audit log to its refusal cap in minutes. `COMPLYOPS_ENV` fails closed to production.

**Residual, recorded.** A sustained flood at the serialised worst case still writes about 202 MiB a day and reaches the 64 MiB refusal cap in about 7.6 hours. Only an edge rate limiter or log rotation bounds the total; the figure is in `docs/DEPLOYMENT.md` for the platform team to size against.

| Test | Expected | Observed | Result |
| --- | --- | --- | --- |
| request body over MAX_CONTENT_LENGTH (256 KiB) | 413 | `413` | Passed |
| 300 refusals from 300 addresses in one window | <= 500 rows (global budget), collapse active | `300` | Passed |

## A05:2021 Security Misconfiguration

All four AMD-001 10.6 headers (Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options) are present on every response including 404, 405 and probe paths. The Content-Security-Policy has no inline script source. Debug mode is off. The diagnostics read-out exposes no key or secret value in either mode. Probe paths answer 200 unauthenticated with no redirect. The container runs as `10001:10001`, from a digest-pinned base, with no package manager.

| Test | Expected | Observed | Result |
| --- | --- | --- | --- |
| security headers on GET /nope (404) | all four AMD-001 headers present | `{'Content-Security-Policy': True, 'Strict-Transport-Security': True, 'X-Content-Type-Op...` | Passed |
| security headers on DELETE /api/registers (405) | all four AMD-001 headers present | `{'Content-Security-Policy': True, 'Strict-Transport-Security': True, 'X-Content-Type-Op...` | Passed |
| security headers on TRACE / (405) | all four AMD-001 headers present | `{'Content-Security-Policy': True, 'Strict-Transport-Security': True, 'X-Content-Type-Op...` | Passed |
| security headers on OPTIONS /console (200) | all four AMD-001 headers present | `{'Content-Security-Policy': True, 'Strict-Transport-Security': True, 'X-Content-Type-Op...` | Passed |
| diagnostics read-out leaks no secret value | no key material or secret in body | `200, key present=False, session key present=False` | Passed |
| debug mode off | app.debug False | `False` | Passed |
| CSP forbids inline script and remote sources | no 'unsafe-inline' in script-src, default-src 'self' or 'none' | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src...` | Passed |
| X-Frame-Options | DENY | `DENY` | Passed |
| 404 body is generic (no stack, no path echo of internals) | no traceback | `<!doctype html> <html lang=en> <title>404 Not Found</title> <h1>Not Found</h1> <` | Passed |
| diagnostics in production leaks no CLIENT_SECRET | secret absent | `200 present=False` | Passed |
| probe / unauthenticated in production | 200, no redirect | `200` | Passed |
| probe /healthz unauthenticated in production | 200, no redirect | `200` | Passed |
| probe /health unauthenticated in production | 200, no redirect | `200` | Passed |
| probe /readyz unauthenticated in production | 200, no redirect | `200` | Passed |
| probe /livez unauthenticated in production | 200, no redirect | `200` | Passed |
| probe /ping unauthenticated in production | 200, no redirect | `200` | Passed |

## A06:2021 Vulnerable and Outdated Components

Not tested by request; tested by the verification loop. `pip-audit` runs against all three hash-locked lockfiles on every change and in Continuous Integration, and returned no known vulnerabilities on this commit. Dependabot raises weekly pull requests for pip, GitHub Actions and Docker. A CycloneDX software bill of materials is produced on every run.

## A07:2021 Identification and Authentication Failures

Production sign-in is a redirect to `login.microsoftonline.com` carrying a PKCE challenge, a state and a nonce bound to the session. A callback with a forged or missing state is refused and recorded. The self-asserted development sign-in is refused while Entra ID is configured, and now through the collapser. Hostile actor values (empty, leading `=`, `-`, `@`, over-length, non-ASCII, double quote) are refused without a server error. Sign-out clears the session.

**Declared deviations.** The identity token signature is not verified; the token is accepted only from the direct back-channel response, per OpenID Connect Core 3.1.3.7. Multi-factor authentication was not checked by the application at the tested commit; it depended on the tenant's Conditional Access policy. **Closed in V2.2:** `claims_from_id_token` now refuses a token whose `amr` claim does not contain `mfa` (seven refused shapes and one end-to-end refusal in `tests/test_entra_sign_in.py`, three mutants killed). The signature deviation stands for the accreditation decision.

| Test | Expected | Observed | Result |
| --- | --- | --- | --- |
| callback with forged state (dev mode) | refused, redirect to sign-in, LOGIN_FAILED recorded | `302 /sign-in` | Passed |
| dev sign-in with hostile actor '' | refused or accepted only if it satisfies the audit boundary, never 500 | `302 signed_in=False` | Passed |
| dev sign-in with hostile actor '=cmd' | refused or accepted only if it satisfies the audit boundary, never 500 | `302 signed_in=False` | Passed |
| dev sign-in with hostile actor '-x' | refused or accepted only if it satisfies the audit boundary, never 500 | `302 signed_in=False` | Passed |
| dev sign-in with hostile actor '@x' | refused or accepted only if it satisfies the audit boundary, never 500 | `302 signed_in=False` | Passed |
| dev sign-in with hostile actor 'aaaaaaaaaaaa' | refused or accepted only if it satisfies the audit boundary, never 500 | `302 signed_in=False` | Passed |
| dev sign-in with hostile actor 'ünïcode' | refused or accepted only if it satisfies the audit boundary, never 500 | `302 signed_in=False` | Passed |
| dev sign-in with hostile actor 'q"uote' | refused or accepted only if it satisfies the audit boundary, never 500 | `302 signed_in=False` | Passed |
| sign-out invalidates the session | subsequent API call unauthenticated | `401` | Passed |
| sign-in page in production mode | 302 to login.microsoftonline.com with PKCE challenge, state and nonce | `https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/auth...` | Passed |
| self-asserted sign-in while Entra configured | refused (302 to sign-in), not signed in | `302 api=401` | Passed |
| callback without a matching session state (production) | refused, no token exchange | `302 /sign-in` | Passed |

## A08:2021 Software and Data Integrity Failures

Dependencies install with `--require-hashes` from a lockfile; the base image is digest-pinned; GitHub Actions are SHA-pinned. The audit chain detected both an edited on-disk entry and a truncated on-disk log, each returning `ok: false, tampered: true` from `/api/audit/verify`, because the anchor is authenticated under the same key and records the count.

| Test | Expected | Observed | Result |
| --- | --- | --- | --- |
| on-disk audit entry modified, then verified | verdict ok=False, tampered=True | `{"ok": false, "tampered": true, "invalidUnderCurrentRules": false, "keyUnavailable": fa...` | Passed |
| on-disk audit log truncated, then verified | verdict ok=False, tampered=True (anchor detects the shortfall) | `{"ok": false, "tampered": true, "invalidUnderCurrentRules": false, "keyUnavailable": fa...` | Passed |

## A09:2021 Security Logging and Monitoring Failures

Every authentication event (LOGIN, LOGIN_FAILED, LOGOUT) and every register mutation writes one chained audit entry with actor, source address and user agent. Refusals are collapsed, never dropped. Verification is an authenticated endpoint. Client errors are generic; detail stays in the server log.

**Gap, recorded.** There is no alerting. AUD-001's five Application Insights alerts were superseded by the App Store decision and the replacement is `TBC, re-verify` pending the AUD-001 amendment.

| Test | Expected | Observed | Result |
| --- | --- | --- | --- |
| authentication events recorded | LOGIN, LOGIN_FAILED, LOGOUT present | `['LOGIN', 'LOGIN_FAILED', 'LOGOUT']` | Passed |
| register mutations recorded | an audit action per create/update | `['TSK_CREATED', 'TSK_CREATED']` | Passed |
| chain verification endpoint | 200 with a verdict | `200 {'ok': True, 'tampered': False, 'invalidUnderCurrentRules': False, 'keyUnavailab` | Passed |

## A10:2021 Server-Side Request Forgery

The only outbound call is the token exchange with Entra ID. The host is a constant, the tenant segment is path-quoted from `TENANT_ID`, and `redirect_uri` is the configured value; a spoofed `Host` header does not change it. No route fetches a caller-supplied URL.

| Test | Expected | Observed | Result |
| --- | --- | --- | --- |
| authorise URL host is fixed, tenant path-quoted | login.microsoftonline.com/<tenant> | `https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/auth...` | Passed |
| redirect_uri is the configured value, not request-derived | configured REDIRECT_URI | `https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/auth...` | Passed |
| Host header spoof does not alter redirect_uri | configured REDIRECT_URI | `https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/auth...` | Passed |

## Actions arising

| Action | Owner | When |
| --- | --- | --- |
| Verify TLS 1.2 or above at `comply-ops.apps.bluestaq.com` and attach the result to the accreditation record | ISM, after first deploy | Before production use |
| User assignment required on the Entra enterprise application: confirmed by the ISM 2026-09-10; single-role access accepted on that basis | ISM | Done |
| MFA evidence: Conditional Access export held by the ISM; `amr` claim check added in V2.2 | ISM | Done, V2.2 |
| Size an edge rate limiter against the A04 residual, or accept it | Platform team, ISM | Before production use |
| Replace the superseded Application Insights alerting, AUD-001 amendment | ISM | `TBC, re-verify` |
| Annual re-test | ISM | September 2027, alongside AMD-001 11.5 |
