# Accreditation review record, AMD-001 section 10.4

Bluestaq Ltd, Compliance Operations Console (`comply-ops`), release V2.2. Drafted for the decision of the UK Information Security Officer. Nothing below is signed until the decision row is completed; the record is then retained in Library 04 per AMD-001 10.4.

**Status: SIGNED, accredited with conditions, 2026-09-10.** The decision is at the foot of this document. The conditions are binding on the deployment, not aspirations, and condition 1 must be discharged within five working days of the first deploy.

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
| Authentication via Entra ID with MFA | **Met, and accepted.** Authorisation code flow with PKCE, state and nonce, in the application against the tenant. The tenant's Conditional Access policy performs MFA. From V2.2 the application refuses any identity token whose `amr` claim does not contain `mfa`, so the policy cannot be silently waived for this application. | `src/complyops/auth.py`, `tests/test_entra_sign_in.py`; Conditional Access policy export covering the `comply-ops` app registration, held by the ISM | Attach the Conditional Access export to this record |
| Authorisation enforcing least privilege | **Met at the tenant; one role in the application.** User assignment is required on the enterprise application (confirmed 2026-09-10). Every assigned user can read and write every register and read the audit log. There is no role separation inside the application. | `auth.required` on every API route; enterprise application assignment list | **Accepted.** Single-role access is proportionate for a single-team console whose access list is the Entra assignment list. Revisit if the user set grows beyond the compliance function. |
| Secure storage of secrets (Azure Key Vault or equivalent) | **Deviated, recorded.** Secrets arrive as App Store environment variables; Azure Key Vault is not available on the platform. No secret is in source or history, verified by pattern grep across the whole history. Be exact about the control, because this row named only half of it: the pre-write hook blocks a credential on this assistant's own edits and sees nothing else, so a human `git add`, a heredoc or a paste never passes through it. The compensating control is the content sweep in `scripts/build-package.sh`, which runs the same patterns over the staged package and whose own limits are recorded there. | `docs/DEPLOYMENT.md` conformance row and Secret channel warning; `.env.example` | Accept the App Store environment as the "equivalent", or not |
| Encrypted communications, TLS 1.2 or above | **Not verified, and not verifiable before deployment.** TLS is terminated by the App Store ingress, outside the application, so there is nothing to measure until a host exists. Strict-Transport-Security is on every response with `includeSubDomains; preload`. | `src/complyops/security_headers.py`; `testssl.sh` or `nmap --script ssl-enum-ciphers` result, to be attached | **Condition 1 of this accreditation.** Measured within five working days of first deploy and attached here. The accreditation lapses if it is not. |
| Input validation and output encoding | **Met, and stated precisely, because this row has been over-claimed before.** The register's `state` field is validated against a closed vocabulary (`records.check_state`). Every other field is validated against a closed set of field NAMES and a length cap (`records.check_fields`), and is then whitespace-stripped, which is a coercion: an unknown field name and an over-length value are both rejected, but the values themselves are free text. The three server-owned fields `id`, `created` and `updated` are a third case again: a caller who submits them has them discarded rather than rejected, so a client cannot set a record's identity or timestamps. Audit fields are the stricter case, with one deliberate exception: a value outside the printable ASCII allowlist is rejected and never transliterated, EXCEPT for the caller-influenced context fields (`source_ip`, `user_agent`, and one `resource_id`), which go through `validation.recordable` and are substituted with the marker `unrecordable` instead. That is intentional and it is a coercion: a header a caller chooses must never veto the writing of an audit entry. The actor is not in that set and a bad actor value still refuses the sign-in. Plus Jinja autoescape; Content-Security-Policy with no inline script; CSRF token on every mutation. 82 OWASP checks at `ec75bd2` (V2.1), none failed; the only code change since is the additive `amr` check, covered by `tests/test_entra_sign_in.py` and a security gate PASS. | `docs/OWASP-TOP-10-TEST.md` A01, A03, A05; `src/complyops/records.py`, `src/complyops/audit/validation.py` | None beyond reading the record |
| Dependency vulnerability scanning | **Met.** `pip-audit` against all three hash-locked lockfiles on every change and in Continuous Integration; Dependabot weekly for pip, GitHub Actions and Docker; CycloneDX SBOM per run; digest-pinned base image; SHA-pinned actions. | `scripts/verify.sh`, `.github/workflows/verify.yml`, `.github/dependabot.yml` | None |
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
| Decision | **Accredited with conditions.** |
| Rationale | Five of the seven confirmations are met and evidenced. One, least privilege, is met at the tenant and accepted as single-role in the application. One, the TLS floor, cannot be measured before a host exists and is carried as condition 1 rather than assumed. The application enforces multi-factor authentication itself from V2.2, so the accreditation does not rest on a tenant policy remaining as configured. |
| Conditions | 1. The TLS 1.2 floor is measured against `comply-ops.apps.bluestaq.com` within five working days of first deploy and the result attached to this record. The accreditation lapses if it is not. 2. The refusal flood residual, about 202 MiB a day reaching the audit log's 64 MiB refusal cap in about 7.6 hours under sustained unauthenticated flooding, is sized by an edge rate limiter or accepted in writing before the application is used by anyone beyond the ISM. 3. The export cadence in `docs/DEPLOYMENT.md` is observed from the first production write, because until an export is uploaded the volume holds the only copy of the log and its anchor. 4. The OWASP Top 10 test is repeated annually alongside the AMD-001 11.5 cycle, first repeat September 2027. |
| Deviations accepted | Secrets as App Store environment variables in place of Azure Key Vault, the platform providing no vault. Identity token signature not verified, accepted only from the direct back-channel response per OpenID Connect Core 3.1.3.7. Audit entries recording field names and never field values, which is stronger than AUD-001 asks. The audit digest keyed and chained beyond AUD-001's plain SHA-256, likewise stronger. No alerting, AUD-001's Application Insights alerts having been superseded by the App Store decision, replacement pending the AUD-001 amendment. SBOM short of the CISA 2026 minimum elements. |
| Not accepted, referred | The AMD-001 11.5 penetration test scope names "Graph API token handling". This build has no Microsoft Graph integration. Referred to Adam Field with the AMD-001 amendment; the clause should read "Entra ID token handling". |
| Reviewer | Ash Higgins, Information Security Manager and Data Protection Lead, as UK Information Security Officer |
| Date | 2026-09-10 |
| Library 04 reference | `TBC, re-verify` |

**This decision accredits the application. It does not authorise the deployment.** The deploy gate returned FAIL at `ee7a1e1` on items outside this review: the Managing Director's sign-off on the App Store target, and three App Store submission fields with no value. Both sit with their owners.
