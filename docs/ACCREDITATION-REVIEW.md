# Accreditation review record, AMD-001 section 10.4

Bluestaq Ltd, Compliance Operations Console (`comply-ops`), release V2.2. Drafted for the decision of the UK Information Security Officer. Nothing below is signed until the decision row is completed; the record is then retained in Library 04 per AMD-001 10.4.

| Item | Value |
| --- | --- |
| Application | `comply-ops`, Bluestaq App Store, `comply-ops.apps.bluestaq.com` |
| Release under review | V2.2, main at merge commit `79fd8b4` (PR #9, 2026-09-10) |
| Reviewer and decision owner | Ash Higgins, Information Security Manager and Data Protection Lead, as UK Information Security Officer |
| Policy | AMD-001 section 10.4, Accreditation |
| Related records | `docs/OWASP-TOP-10-TEST.md` (AMD-001 10.6 pre-deployment test), `docs/DEPLOYMENT.md` (conformance table, recorded decisions, deviations) |

## The seven confirmations

AMD-001 10.4 names seven things the review must confirm. Each row says what exists, where to look, and what the reviewer still has to see for themselves.

| Confirmation | Position | Evidence | Reviewer action |
| --- | --- | --- | --- |
| Authentication via Entra ID with MFA | **Met.** Authorisation code flow with PKCE, state and nonce, in the application against the tenant. The tenant's Conditional Access policy performs MFA. From V2.2 the application refuses any identity token whose `amr` claim does not contain `mfa`, so the policy cannot be silently waived for this application. | `src/complyops/auth.py`, `tests/test_entra_sign_in.py`; Conditional Access policy export covering the `comply-ops` app registration, held by the ISM | Attach the Conditional Access export to this record |
| Authorisation enforcing least privilege | **Met at the tenant; one role in the application.** User assignment is required on the enterprise application (confirmed 2026-09-10). Every assigned user can read and write every register and read the audit log. There is no role separation inside the application. | `auth.required` on every API route; enterprise application assignment list | Accept single-role access for a single-team console, or require role separation as a V2.x change |
| Secure storage of secrets (Azure Key Vault or equivalent) | **Deviated, recorded.** Secrets arrive as App Store environment variables; Azure Key Vault is not available on the platform. No secret is in source or history; the pre-write hook blocks one before it lands. | `docs/DEPLOYMENT.md` conformance row and Secret channel warning; `.env.example` | Accept the App Store environment as the "equivalent", or not |
| Encrypted communications, TLS 1.2 or above | **Not yet verified.** TLS is terminated by the App Store ingress, outside the application. Strict-Transport-Security is on every response. The protocol and cipher floor must be measured against the live host after first deploy. | `src/complyops/security_headers.py`; `testssl.sh` or `nmap --script ssl-enum-ciphers` result, to be attached | Run or commission the scan after first deploy; attach the result |
| Input validation and output encoding | **Met.** Every register field validated against a closed vocabulary and rejected rather than coerced; audit fields printable ASCII by allowlist; Jinja autoescape; Content-Security-Policy with no inline script; CSRF token on every mutation. 82 OWASP checks at `ec75bd2` (V2.1), none failed; the only code change since is the additive `amr` check, covered by `tests/test_entra_sign_in.py` and a security gate PASS. | `docs/OWASP-TOP-10-TEST.md` A01, A03, A05; `src/complyops/records.py`, `src/complyops/audit/validation.py` | None beyond reading the record |
| Dependency vulnerability scanning | **Met.** `pip-audit` against both hash-locked lockfiles on every change and in Continuous Integration; Dependabot weekly for pip, GitHub Actions and Docker; CycloneDX SBOM per run; digest-pinned base image; SHA-pinned actions. | `scripts/verify.sh`, `.github/workflows/verify.yml`, `.github/dependabot.yml` | None |
| Inclusion in the annual penetration test scope | **Met in policy, scope note needs amendment.** AMD-001 11.5 names the application from the September 2026 cycle. The 11.5 scope lists "Graph API token handling"; this build has no Microsoft Graph integration, so that item is void and should read "Entra ID token handling". | AMD-001 11.5; `CLAUDE.md` (no SharePoint or Graph) | Amend 11.5 wording with the AMD-001 update |

## Deviations before the reviewer

Each is deliberate, each is documented at the reference, and each needs a decision recorded here.

● **Identity token signature not verified.** Accepted only from the direct back-channel response to the application's own POST carrying its client secret, per OpenID Connect Core 3.1.3.7. Issuer, audience, expiry, nonce and `amr` are checked. Adding signature verification means a JSON Web Key Set fetch and an RSA dependency. `docs/DEPLOYMENT.md`, Known gaps.
● **Secrets as environment variables, no Key Vault.** Above.
● **Audit log records field names, never values.** Stronger privacy than AUD-001's data column asks for; recorded in `CLAUDE.md` and `docs/DEPLOYMENT.md`.
● **Audit digest keyed and chained, beyond AUD-001's plain SHA-256.** Stronger than the policy on every axis; recorded in `CLAUDE.md`.
● **No alerting.** AUD-001's Application Insights alerts were superseded by the App Store decision; replacement `TBC, re-verify` pending the AUD-001 amendment.
● **Refusal flood residual.** About 202 MiB a day at the serialised worst case, about 7.6 hours to the audit log's 64 MiB refusal cap under sustained unauthenticated flooding; only an edge rate limiter or log rotation bounds the total. `docs/DEPLOYMENT.md`, Deferred by design.

## Conditions the reviewer may attach

Suggested, not decided:

1. TLS floor verified against the live host within five working days of first deploy, result attached to this record.
2. Edge rate limiter sized against the flood residual, or the residual accepted in writing, before production use by anyone other than the ISM.
3. Export cadence per `docs/DEPLOYMENT.md` observed from the first production write, because until an export is uploaded the volume holds the only copy of the log.
4. Annual OWASP re-test alongside the AMD-001 11.5 cycle.

## Decision

| Field | Entry |
| --- | --- |
| Decision | Accredited for production / Accredited with conditions / Not accredited (delete two) |
| Conditions | |
| Deviations accepted | |
| Reviewer | Ash Higgins, UK Information Security Officer |
| Date | |
| Library 04 reference | |
