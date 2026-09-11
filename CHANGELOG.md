# Changelog

Bluestaq Compliance Operations Console (`comply-ops`). One row per release, recording the
version, the commit it shipped from, the binding gate verdicts, and the deviations open at
that point. AMD-001 section 10.3 governs the commit messages behind each row; this file is
the release-level record the deploy gate reads.

Dates are UTC. A release is not "shipped" until it is deployed, and nothing has been
deployed yet, so every row below records a release that was cut, gated and merged.

## V2.2, 2026-09-10, `ee7a1e1` and the packaging change that follows it

**Gates.** Recorded in `docs/GATE-RECORDS.md`, with the commit each ran against. Security
review PASS at `b3b798c`, then eleven further runs against the packaging and verification
machinery, every one of them FAIL and every finding in that machinery or in a shipped
document rather than in the application. Deploy gate **FAIL**, first run, at `ee7a1e1`.
Engineering review **FAIL** at `c4a33cf`, on the Continuous Integration bill of materials
still describing the pre-split dependency tree and on a test count in this file that had
never been measured. Verification loop PASS at `d5eef89`, 874 passed, 2 skipped, coverage
98.98%, measured at that commit rather than at the commit this row is headed by. The test count here was once replaced with a LATER commit's figure while the commit
name stayed, inside the sentence below that criticises that very mistake; both halves are now
measured at the commit named. An earlier row here recorded a 98.84 to 98.89 range and was not
re-measured when the test count beside it was updated, which is the same defect this file
records against others.

**Changed.**

● Multi-factor authentication is enforced by the application. `claims_from_id_token`
  refuses an identity token whose `amr` claim is not a list containing `mfa`, so a
  Conditional Access policy that is scoped down, excluded for an account, or bypassed
  produces a refused sign-in and a `LOGIN_FAILED` row rather than a verified actor on the
  audit log. AMD-001 section 10.4.
● The dependency lockfiles split three ways: `requirements-runtime.txt` for the image,
  `requirements.txt` for the platform's test stage and dependency scan, `requirements-dev.txt`
  for the local loop. The previous single-file shape could not have deployed: the platform
  runs `pip install -r requirements.txt` then pytest, and a runtime-only file fails that
  stage with every later stage skipped. The three nest at the `.in` level and the subset
  relation is asserted by the loop and by the suite.
● `scripts/build-package.sh` and `scripts/simulate-pipeline.sh`. The artefact that would be
  uploaded had never been built or tested; both failures found by running it are now
  assertions in the build script.
● The credential sweep over the staged package, and the matching pre-write hook, catch an
  UNQUOTED assignment. Every secret this application consumes is written without quotes, so
  the previous rule covered none of them: `CLIENT_SECRET=...` in `.env.example` built clean
  and shipped at the package root. The rule now tolerates an `ENV`, `ARG`, `export`, `-e`,
  `--env` or list-marker prefix at any indent, a second rule catches the same names in a
  document parameter table, and both compile with MULTILINE as well as IGNORECASE, without
  which they matched only at the first byte of a file and a UTF-16 credential below line one
  shipped. Measured at zero false positives across every tracked file. `NAME = value` with
  spaces stays uncaught and is recorded as an open limit under Open in scope in
  `docs/GATE-RECORDS.md`: closing it flags sixteen ordinary constants here.
● `.gitignore` refuses `.env.*` with `.env.example` excepted. The suffix list it replaced
  missed `.env.production`, `.env.prod` and `.env.staging`, and no hook sees a human
  `git add`, so the ignore file is the only control on that path into the history.
● `docs/OWASP-TOP-10-TEST.md`, the AMD-001 10.6 pre-deployment test, 82 checks, none failed.
● `docs/ACCREDITATION-REVIEW.md`, the AMD-001 10.4 review. **Signed, accredited with
  conditions**, by Ash Higgins as UK Information Security Officer, 2026-09-10.
● `docs/GATE-RECORDS.md`, so a gate verdict is an artefact in the tree rather than a claim
  in a commit message. Two separate gates failed on exactly that absence.
● The shipped image is one layer again. A `WORKDIR /app` after the flattening `COPY` cost a
  second one; gunicorn takes `--chdir /app` instead. Measured on a real build, 2 layers
  before and 1 after, booting in production mode with the chain intact.
● Rollback for a first release is deletion of the application on the platform, confirmed by
  the ISM. Deletion does not revert the volume, which is the part that matters.

**Deviations open at this release.** Secrets as App Store environment variables rather than
Azure Key Vault. Identity token signature not verified, back-channel only, OpenID Connect
Core 3.1.3.7. Audit entries record field names and never field values. The audit digest is
keyed and chained, stronger than AUD-001's plain SHA-256. No alerting, AUD-001's Application
Insights alerts superseded by the App Store decision, replacement `TBC, re-verify`. Refusal
flood residual of about 202 MiB a day, reaching the audit log's 64 MiB refusal cap in about
7.6 hours under sustained unauthenticated flooding. SBOM short of the CISA 2026 minimum
elements. No CSV exporter for the AUD-001 annual export. No scheduled base-image rebuild.

## V2.1, 2026-08-27, `e45c156`, merged to main at `07270bf`, and `ec75bd2`

**Gates.** Engineering review PASS. Security review PASS at round twelve, after eleven
rounds of findings, each fixed and re-attacked. Verification loop PASS.

**Changed.** The console itself: the task, incident and risk registers on an atomic durable
store; the persistent chained audit journal with its keyed anchor; Entra ID sign-in; the
health and diagnostics paths; the AMD-001 10.6 security headers. Then the refusal collapser
and its bounds, which took rounds seven to twelve: an unauthenticated caller could fill the
audit log to its refusal cap, and each of the first three fixes was measured and found
short of what it claimed.

## V2.0, 2026-08-20, `e1cd87f`

**Changed.** The App Store Python scaffold and the audit hash chain, keyed and anchored,
with the storage probe bounded and `/healthz` registered. No release record was kept at the
time; this row is reconstructed from the commit history and carries no gate verdicts,
because none is recorded.
