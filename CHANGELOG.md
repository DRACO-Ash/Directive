# Changelog

Bluestaq Compliance Operations Console (`comply-ops`). One row per release, recording the
version, the commit it shipped from, the binding gate verdicts, and the deviations open at
that point. AMD-001 section 10.3 governs the commit messages behind each row; this file is
the release-level record the deploy gate reads.

Dates are UTC. A release is not "shipped" until it is deployed, and nothing has been
deployed yet, so every row below records a release that was cut, gated and merged.

## V2.2, 2026-09-10, `ee7a1e1` and the packaging change that follows it

**Gates.** Recorded in `docs/GATE-RECORDS.md`, with the commit each ran against. Security
review PASS at `b3b798c`, then a run per fix against the packaging and verification
machinery, recorded row by row in `docs/GATE-RECORDS.md`, every one of them FAIL and every
finding in that machinery or in a shipped document rather than in the application. Deploy gate **FAIL**, first run, at `ee7a1e1`.
Engineering review **FAIL** at `c4a33cf`, on the Continuous Integration bill of materials
still describing the pre-split dependency tree and on a test count in this file that had
never been measured. The verification loop is red at some commits of this release and green
at others; `docs/GATE-RECORDS.md` carries the verdict, the test count and the coverage for
each commit a gate ran against, in the row for that commit. No count is restated here,
because this paragraph has got one wrong three separate ways: a figure replaced with a LATER
commit's while the commit name stayed, inside the sentence that criticised that very
mistake; a coverage range left un-re-measured when the count beside it changed; and a count
that was correct when written and stale one commit later, in the commit written to stop
exactly that. A figure describing the current tree does not belong in a release note.

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
  the previous rule covered none of them: an unquoted client secret in `.env.example` built
  clean and shipped at the package root. Three gate rounds went into the pattern set, each
  of them demonstrating a shape that still shipped. It now matches an assignment at the
  start of a line behind any `ENV`, `ARG`, `export`, `-e`, `--env` or list-marker prefix at
  any indent and behind an optional quote or backtick; the same assignment anywhere in a
  line of prose; and a credential-shaped token in any cell of a document parameter table
  row. Everything compiles with MULTILINE, and with IGNORECASE except the prose rule,
  which must not fold case. Without MULTILINE the anchored
  rules matched only at the first byte of a file and a UTF-16 credential below line one
  shipped. The live rules produce 1 finding across every tracked file, and it is the
  declared test double the exemption ledger pins by path, digest and match count. What is
  still
  open is listed under Open in scope in `docs/GATE-RECORDS.md` rather than implied to be
  closed, and the largest item is `NAME = value` with spaces: closing it gives 22 findings
  on 22 lines across every tracked file, the experiment being to replace `=` with
  `[ \t]*=[ \t]*` in that rule alone. Every figure in this bullet is asserted by
  `tests/test_sweep_cost_figures.py`, against the live tree and against this sentence.
● The sweep and the pre-write hook are asserted to be one rule set by
  `tests/test_secret_rule_parity.py`, patterns and flags compared character for character,
  with one named exception. Both files claimed to be in step in a comment, and the claim
  was false twice. The same module also EXECUTES the hook against a probe per rule: the text
  comparison alone was defeated by leaving the rule array untouched and iterating only its
  first element, which stopped twelve of thirteen rules blocking with the suite green.
  It now also asserts WHICH fields of a write reach the rules, that a write is scanned
  whatever file it is aimed at and however long it is, that both registration files carry
  the matcher, and that each registration points at a hook that exists and is this one.
  Narrowing the hook's input collection to one field blinded it to every `Edit` and
  `MultiEdit` with the suite green. So did a `file_path` carve-out for
  `.env`, a 400-byte length bound, and a registration pointing at a filename that does
  not exist. Which rules run, which fields are read, what those rules see, and whether
  the hook runs at all are four separate controls, and each was found by a reviewer
  defeating the tests written for the one before it.
● `tests/test_sweep_cost_figures.py` re-measures the three costs that justify the three
  open gaps, asserts the sentences that report them, and sweeps every tracked file for
  anything written in the same shapes. All three parts, because six attempts at this class
  each closed one and left the next open: the measurement, then the prose reporting it, then
  the files outside the declared three, then the clauses inside a pinned sentence. Every
  figure is a digit now, because a figure written as a word is invisible to any scanner.
● `tests/test_house_voice_hook.py` executes the house-voice hook once per registered tool.
  Nothing referenced that hook at all, and it had shipped unable to read a notebook write
  while registered for one. Four figures in shipped files
  went stale before it existed, one of them written stale in the commit that measured
  it. A number in prose is an argument nobody can check.
● `.gitignore` refuses `.env.*` with `.env.example` excepted, and the same key and
  certificate family the packaging sweep refuses inside a package. The two controls
  disagreed: an `audit.key` at the repository root was trackable and is outside the package
  allowlist, so nothing downstream would ever have seen it, and the deployment runbook tells
  the operator to generate that key with `openssl rand -hex 32`. No hook sees a human
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
