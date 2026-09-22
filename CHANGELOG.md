# Changelog

Directive (`directive`). One row per release, recording the
version, the commit it shipped from, the binding gate verdicts, and the deviations open at
that point. AMD-001 section 10.3 governs the commit messages behind each row; this file is
the release-level record the deploy gate reads.

Dates are UTC. A release is not "shipped" until it is deployed, and nothing has been
deployed yet, so every row below records a release that was cut, gated and merged.

## V2.3, 2026-09-22, `a3741c8` and the fixes that follow it

**Gates.** `deploy-gate` **FAIL** at `a3741c8`, on five blockers: neither binding review had
seen the tree, the Managing Director's sign-off was outstanding, four required submission
fields had no value, the signed accreditation described a three-register application while
the package shipped five, and the version had not moved since 2026-09-10 although 1,778
lines had. `security-reviewer` **FAIL** at `a3741c8`, two MAJORs and two MINORs, every one
in application code rather than build machinery. It held the generated form against five
cross-site scripting payloads, the drawer's patch path against missing and wrong tokens,
referential integrity against traversal and oversize values, and the Article 28(2) invariant
against six routes, and it proved eight of nine new controls by deleting them.

Both gates then returned **FAIL** again at `f2e12f8`, the commit that answered them, and
both were right. The version bump had disarmed the test holding the packaging version
guard, so the verification loop was red and, under `set -eu`, the dependency scan, the bill
of materials and the lockfile nesting legs never ran. That commit's message asserted a pass
count measured against a different tree, which is the rule the two previous FAILs were
about. Three shipped records were wrong. And the security gate found that a complete
transfer risk assessment could not be created at all. Every row, with what each gate found,
is in `docs/GATE-RECORDS.md`. Not one finding across either run was in the running
application's security controls: the register fixes held under mutation, the Article 28(2)
invariant held on six routes to APPROVED, and the 27-check evidence record reproduced
independently.

**Changed.**

● **Fields have a KIND.** Text stays capped; a date is an ISO calendar date; a choice is a
  closed vocabulary; a link names a record in another register. Field acceptance is scoped
  to the REGISTER rather than the application, so a task cannot carry a transfer agreement.
  Until this release the application held a compliance operating rhythm with no concept of
  when anything was due, and a risk register with no severity.
● **Two registers for the restricted transfer.** `agreements` holds the International Data
  Transfer Agreement and records the controller, exporter, importer and the importer's role
  from a closed vocabulary. `transfers` holds the Transfer Risk Assessment and REQUIRES the
  agreement it assesses; a link to an agreement that does not exist is refused rather than
  stored.
● **UK GDPR Article 28(2) is held by the application.** A transfer assessment cannot reach
  `APPROVED` while the controller's authorisation is unset or `NOT_OBTAINED`, and the
  refusal names the article and says what to record. First rule in this build that reasons
  about a record as a whole rather than field by field.
● **The console generates its form from the schema**, so a field added to a register appears
  without a second edit, and a record opens in a drawer where every field is readable and
  editable. Before this a record was write-only: the interface could not create a transfer
  assessment at all, because `agreement` is required and no form offered it.
● **The application is renamed to Directive**, slug `directive`, package `src/directive`,
  environment prefix `DIRECTIVE_ENV`, host `directive.apps.bluestaq.com`.
● **The audit boundary caps a field NAME, and its total cap is measured.** At a
  128-byte total, a transfer risk assessment naming all thirteen of its declared fields and
  a starting state joined to 132 bytes, so the audit boundary refused the entry and the
  create answered 400: the flagship register could not be created in full at all. Found by
  the security gate, and it survived because nothing exercised the register declaration
  against the audit cap; the console cannot reach it either, since the create form renders
  the required fields only.
  The obvious fix was wrong and is worth recording. That 128 was itself a deliberate
  tightening from 512, made to stop record content wearing a field name's clothes, so simply
  raising the number would have undone a privacy control to fix an availability one. The
  sentence that tightening was aimed at is 79 bytes: it passed a 128-byte TOTAL cap on its
  own and was only ever caught when doubled. A total cap was always a proxy for a rule about
  each NAME. So the per-name cap is now explicit at 48 bytes, which refuses that sentence at
  the first occurrence and keeps refusing it however many fields a register grows, and the
  total is 256, which carries only what it claims: no single entry dominates the log. The
  longest name any register declares is `data_categories` at 15 bytes. Both figures are held
  by tests measured against the registers rather than asserted.
● **The shipped records caught up with the five-register reality**, which was a deploy-gate
  blocker in its own right. `README.md` describes what the application holds. The OWASP Top
  10 record carries a V2.3 addendum of 27 checks actually sent against the two new registers,
  27 passed, with two observations recorded rather than closed: a refused state transition
  writes no audit entry, and the Article 28(2) invariant reads the assessment's own
  authorisation field rather than the linked agreement's importer role. The accreditation
  record carries a re-review addendum, drafted and deliberately unsigned, naming which of the
  seven AMD-001 10.4 confirmations this release touches. `docs/DEPLOYMENT.md` names all five
  state vocabularies rather than the first three.

**Fixed.**

● **A no-op update wrote a permanent audit entry.** A double click on a state button put an
  immutable signed row with an empty `fields_changed` into the evidence an assessor reads.
  The test that should have caught it asserted the weaker property that the entry claimed no
  transition, which was true of the defect.
● **Every agreement was issued the identifier `IDTA-0001`.** `next_id` matched rows against
  a three-letter prefix pattern, false of the four-character `IDTA`, so no existing record
  ever matched. Three controls failed together: the audit entry's `resource_id` named the
  same record for all of them, only the first could be read or corrected, and a transfer
  assessment's link passed referential integrity against an identifier naming several
  different agreements.
● **A date was coerced rather than rejected.** `date.fromisoformat` accepts the whole ISO
  8601 grammar, so `2026-W01-1` was stored as `2025-12-29`, a year earlier than typed, on
  the review date an assessor reads. Combined with the no-op guard it returned HTTP 200 and
  wrote no entry at all. This broke the hard rule that a field is rejected at the boundary
  and never coerced.
● **A required field could be emptied by a partial update.** The requirement held at
  creation and gave no protection afterwards, so a title could be blanked and the record
  left with no name in any list an assessor reads. `agreement` was not exposed: its link
  format rejects an empty string first, so it survived by accident rather than by design.
● **A tightened identifier grammar was held by no test.** The LINK format gate moved from
  Unicode-aware `\d` to `[0-9]`, so both halves of one identifier grammar agree, and the
  whole suite stayed green with the tightening reverted: every existing test sent a
  well-formed identifier, which passes the format gate and dies a layer later at
  referential integrity, so the refusal line never executed. Third finding in a row about a
  control left unheld, which is the pattern rather than the incident.
● **The version bump disarmed the test holding the packaging version guard.** The test
  pinned the literal `version = "2.2"` to spoil the manifest, so bumping to 2.3 made the
  line a no-op and the test died on git's exit code rather than on the control. The guard
  in `scripts/build-package.sh` was left held by no passing test, and the verification loop
  was red. The version is now read out of the manifest and the substitution is asserted to
  have bitten, so the next bump cannot orphan the probe again.

**A note on the figures in this file.** Every count and percentage here was measured on the
tree it describes. Two were not, earlier in this release, and both were caught by a gate: a
pass count taken from a run against a different tree, and a coverage figure truncated from
one run and quoted against another. `docs/GATE-RECORDS.md` carries both. The rule in
`CLAUDE.md` is to measure a figure before asserting it, and this release broke it twice
before it held.

**Open at this release.** The Managing Director's sign-off on the App Store target. Four
submission fields: visibility, category, short description, full description. The
`securityContext.fsGroup` and single sign-on gateway exemption requests. The container image
has never been built or run, so its non-root user, setuid sweep, absent package manager and
single layer are held by reading and by tests rather than by probing a built image.

**A note on the commit references in this file and in `docs/GATE-RECORDS.md`.** History was
rewritten on 2026-09-13 to excise two policy instruments from it, at the owner's
instruction. Every commit identifier recorded before that date names an object that no
longer exists in this repository. The verdicts are unchanged and the records are otherwise
accurate; the identifiers are not resolvable and should be read as naming the pre-rewrite
lineage.

## V2.2, 2026-09-10, `ee7a1e1` and the packaging change that follows it

**Gates.** Recorded in `docs/GATE-RECORDS.md`, with the commit each ran against. Security
review PASS at `b3b798c`, then a run per fix against the packaging and verification
machinery, recorded row by row in `docs/GATE-RECORDS.md`, every one of them FAIL and every
finding in that machinery or in a shipped document rather than in the application. Deploy gate **FAIL**, first run, at `ee7a1e1`.
Engineering review **FAIL** at `c4a33cf`, on the Continuous Integration bill of materials
still describing the pre-split dependency tree and on a test count in this file that had
never been measured. The verification loop is red at some commits of this release and green
at others, and `docs/GATE-RECORDS.md` carries the commit, the verdict and the findings for
each gate run. It records no test count and no coverage figure, and neither does this
paragraph, because a figure describing a tree does not belong in a release note: this one
has carried a wrong count three separate ways, most recently in the commit written to stop
exactly that. The sweep-cost figures in this
file are read back by `tests/test_sweep_cost_figures.py`. The others are measurements
recorded at the time they were taken, and they are not read back: the 82 pre-deployment
checks, the image layer count, and the refusal-flood sizing. Saying more than that is how
this paragraph has been wrong four times, twice in the sentence written to fix the last
one.

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
  clean and shipped at the package root. Several gate rounds went into the pattern set, each
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
  closed, and the largest item is `NAME = value` with spaces: closing it gives 24 findings
  on 24 lines across every tracked file, the experiment being to replace `=` with
  `[ \t]*=[ \t]*` in that rule alone. The sweep-cost figures in this bullet are asserted by
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
  anything written in the same shapes. Every part of that was added only because an earlier attempt at it
  closed one and left the next open: the measurement, then the prose reporting it, then
  the files outside the declared three, then the clauses inside a pinned sentence. Every
  figure the module reads back is a digit, because one written as a word is invisible
  to any scanner.
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
