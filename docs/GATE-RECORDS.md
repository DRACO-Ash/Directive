# Gate records

Every binding gate verdict, in the repository, because "the claim exists only as a claim"
has now been raised twice: once by the deploy gate, which could not corroborate an
engineering review for V2.2, and once by that engineering review, which could not
corroborate the security review it was told about. A verdict recorded only in a commit
message or a chat transcript is an assertion, not evidence. This file is the artefact.

Each row names the commit the gate actually ran against, which is not always the commit
that merged. Where a verdict predates this file and cannot be recovered from the tree, the
row says so rather than reconstructing it.

## V2.2

| Date | Gate | Commit | Verdict | What it found |
| --- | --- | --- | --- | --- |
| 2026-09-10 | `security-reviewer` | `b3b798c` | **PASS** | 25 hostile `amr` shapes refused with `AuthError` only; ordering, end-to-end refusal and three mutants confirmed; three OWASP rows reproduced. Two MINORs on record accuracy, fixed in `5f17427`. |
| 2026-09-10 | `deploy-gate`, first run | `ee7a1e1` | **FAIL** | Container contract held under probing on a built and running image. Failed on the wrapper: no upload package had ever been built or tested, no rollback, accreditation unsigned, Managing Director sign-off outstanding, three submission fields undefined, engineering review not corroborated. One MINOR: 2 image layers, not 1. |
| 2026-09-10 | `engineering-reviewer` | `c4a33cf` | **FAIL** | Two MAJORs. The Continuous Integration dependency scan and software bill of materials still targeted `requirements.txt` after the lockfile split, so the artefact described 15 components against the 9 the image carries and the shipping tree was scanned nowhere in Continuous Integration. And `CHANGELOG.md` asserted "790 tests", a figure measured at neither commit it covered. Six MINORs. The `amr` check, the split and the packaging scripts were mutation-proven sound. |
| 2026-09-10 | `engineering-reviewer`, second pass | `a92a5ff` | **FAIL** | One BLOCKER. The `shellcheck` leg added in the previous fix had only ever been observed taking its skip path; with the binary present it exited 1 on two findings in `scripts/simulate-pipeline.sh`, and since the loop is `set -eu` with that leg second, every later leg was skipped. In Continuous Integration the step precedes all others, so the binding job would have been red. Three MINORs, including the accreditation record over-claiming register field validation. |
| 2026-09-10 | `engineering-reviewer`, third pass | `a0ac9b5` | **FAIL** | One MAJOR: the register-validation over-claim was corrected in the accreditation summary row but left standing in `docs/OWASP-TOP-10-TEST.md`, the evidence that row cites. Six MINORs, including a duplicated clause introduced by the fix itself and a stale `dist/latest` pointer that could make the pipeline simulation report PASS for a tree whose package never built. |
| 2026-09-10 | `engineering-reviewer`, fourth pass | `3a0661f` | **PASS** | Six MINORs, all advisory: an over-claim in the retrospective section of this file, an unstated third disposition for the server-owned register fields, a silent skip when git is absent, a filename match looser than it read, a residual that still admitted a package built before an uncommitted edit, and a 313-character line. |
| 2026-09-10 | `engineering-reviewer`, fifth pass | `973378d` | **FAIL** | One MAJOR: the `-dirty` stamp added for the previous pass caught only a build made on an already-dirty tree, never an edit made after the build, so the gap its own comment claimed to close was still open and still reached SIMULATION: PASS. Four MINORs. |
| 2026-09-10 | `security-reviewer`, supply chain and build machinery | `973378d` | **FAIL** | Five MAJORs, two of them holes in the script that decides what leaves this repository: a git-ignored `src/.env` shipped inside a clean-stamped package, and a symlink in an allowlisted directory exfiltrated content from outside the tree because the archiver dereferences it. Also the staleness gap above, `packaging` shipping in the image while audited and inventoried by nothing, and the register-validation over-claim in a third document. Four MINORs. |
| 2026-09-11 | `security-reviewer`, second run | `3ead4dd` | **FAIL** | One MAJOR: `cp` dereferences a symlinked INTERMEDIATE component, so the fix narrowed the class rather than closing it. Eight MINORs. |
| 2026-09-11 | `security-reviewer`, third run | `e0095df` | **FAIL** | Four MAJORs. `git archive` honours `.gitattributes` and host conversion config, so `export-ignore` deleted a security control's test from the package with the build green; the credential sweep skipped anything it could not decode; `skip-worktree` reports uppercase and the guard matched lower case only; and no test held any of it. |
| 2026-09-11 | `security-reviewer`, fourth run | `533fa5c` | **FAIL** | Three MAJORs. The exemption matched `tests` anywhere in the absolute path; UTF-16 carried a plain credential through the sweep; twenty-one controls survived deletion with the suite green. |
| 2026-09-11 | `security-reviewer`, fifth run | `496f312` | **FAIL** | Three MAJORs. The pointer temporary race was still open at the `mv`; the exemption budget counted lines rather than matches or paths; and the coverage claim written for the previous MAJOR was itself false. |
| 2026-09-11 | `security-reviewer`, sixth run | `102df44` | **FAIL** | Four MAJORs and a MINOR set. The pointer race survived `mktemp` because the shell re-opens the name; the exemption budget counted rule labels rather than credentials, so three secrets of one shape spent a budget of one; the simulation's central red-suite guard was held by no test; and the coverage claim written for the previous MAJOR over-claimed again, the sixth document in that class. |
| 2026-09-11 | `security-reviewer`, seventh run | `ab16c1b` | **FAIL** | Four MAJORs. The manifest write was a fourth predictable name in `dist/` and fell to the same symlink race on the first attempt; the pointer fix and the exemption match count were both held by no test, so reverting either left the suite green; and two shipped documents over-claimed, one asserting a deletion matrix that did not exist. |
| 2026-09-11 | `security-reviewer`, eighth run | `ef9c3f2` | **FAIL** | Three MAJORs. The `mktemp -d` work directory was held by no test; the test named for the `coverage.xml` guard was satisfied by an `echo` beneath it; and the deployment note claimed a deletion-matrix row per gate run against four rows for eight runs. |
| 2026-09-11 | `security-reviewer`, ninth run | `52f3e14` | **FAIL** | Two MAJORs. The work-directory test asserted a literal name and, in its own docstring, a mode it never read, so a fixed name and a `chmod 755` both survived. And this table's eighth row carried a figure the source did not support. |
| 2026-09-11 | `security-reviewer`, tenth run | `2819cf5` | **FAIL** | First run scored against the stated threat model. Three binding MAJORs: the credential sweep only matched a QUOTED assignment, so an unquoted `CLIENT_SECRET=...` in `.env.example` shipped at the package root, demonstrated end to end; the accreditation record pointed at a limits list that did not name it; and four constant-time comparisons were held by no test, replacing each with `==` leaving all 845 green. The reviewer endorsed the boundary and named two under-specifications, both since written in. |
| 2026-09-11 | `security-reviewer`, eleventh run | `ff2c5d7` | **FAIL** | One BLOCKER and five MAJORs. The Accepted residual row written in that very commit spelled two probe names out in full, so the sweep matched its own record and the build refused: no package, twenty red tests, the loop exit 1. The new unquoted rule was anchored to the start of a line, so the same credential behind `ENV`, `ARG`, `-e` or a bullet, or between the pipes of a parameter table, shipped. The sweep compiled without MULTILINE, which made both anchored rules dead in exactly the NUL-stripped pass that exists to see a UTF-16 credential. `.gitignore` missed `.env.production`, `.env.prod` and `.env.staging`. And two controls were held by no test: the `.env.example` filename exemption and `set -e` in the simulation. |
| 2026-09-11 | `security-reviewer`, twelfth run | `5e28df4` | **FAIL** | Four MAJORs, three of them demonstrated by a package that built green while shipping a live-shaped client secret in a document. The table rule read the cell after the name and the table it was written for has three columns, so it scanned Source and never the column headed Value. A backtick between the bullet and the name defeated the whole prefix set, which is this project's own house style. The ignore rules left the whole key and certificate family trackable, and those names are outside the package allowlist, so the sweep that refuses them inside a package would never have seen one at the repository root. And the Open in scope section recorded none of it. |
| 2026-09-11 | `engineering-reviewer`, sixth pass | `5e28df4` | **FAIL** | Three MAJORs, one shared with the run above. The `$PWD` clause of the simulation's location assertion was held by no test: the guards above it fire first with a different message, and deleting it left all eleven simulation tests green. And two rule sets were duplicated across two runtimes with no parity test, in a delta whose own comment records that they had diverged. |
| 2026-09-11 | `security-reviewer`, thirteenth run | `6d9394f` | **FAIL** | Four MAJORs. The hook's BEHAVIOUR was held by no test: leaving its rule array untouched and iterating only its first element stopped twelve of thirteen rules blocking with every parity test green, because the parity test compares rule text and nothing executed the hook. `ssh-keygen -t ed25519` writes an extensionless file that neither `*.pem` nor `*.key` matches, so an OpenSSH private key was still trackable. And two figures in shipped documents were not supported: 23 keyword arguments against 19 measured, and 156 tracked files against 157. |
| 2026-09-11 | `security-reviewer`, fourteenth run | `72ab2d0` | **FAIL** | Three MAJORs. The hook was blinded again, this time by narrowing WHAT it reads rather than which rules it runs: every probe reached it through `tool_input.content`, so cutting `new_string`, `file_text` and the `edits` loop left all twenty-one tests green while every `Edit` and `MultiEdit` write stopped being scanned. Eight of the eleven filename patterns could be deleted with the suite green, because one test probed one name. And two cost figures in shipped files were unsupported. |
| 2026-09-11 | `engineering-reviewer`, seventh pass | `72ab2d0` | **FAIL** | Three MAJORs, all three shared with the run above or its consequence: the five filename patterns added in that delta were held by no test; "eleven of twelve rules" was twelve of thirteen; and the leading-part cost figure read 12 where 9 findings in `src/` is measurable, eight of them `key_id=`. It also confirmed the hook-execution tests hold the rule set, and that the two former skips cannot flake. |
| 2026-09-11 | `security-reviewer`, fifteenth run | `1bdbdb8` | **FAIL** | Three MAJORs. The hook was defeated a THIRD way, by a dimension the previous two rounds did not cover: what the rules see. A one-line `file_path` carve-out exempting `.env` passed all twenty-seven tests while letting a client secret into `.env.production`, and a `.slice(0, 400)` let a credential past 400 bytes into any document, because every probe was a short single line with no path. The registration test asserted the substring `secret-scan`, so pointing both files at a hook that does not exist was green. And a fourth cost figure was stale in two shipped documents and in the sweep, which contradicted itself about one experiment 154 lines apart. |
| 2026-09-11 | `engineering-reviewer`, eighth pass | `1bdbdb8` | **FAIL** | Four MAJORs, three of them created by the delta under review. A count written stale in the commit that grew the list it counted; the same fourth figure; the filename mirror drifting in the ADD direction, where a pattern with no probe was green; and a `pytest.skip` reintroduced forty lines below the comment condemning the one it removed. It confirmed by mutation that the sweep, the hook's reach and the rule set are all genuinely held. |
| 2026-09-11 | both gates, re-run | `TBC, re-verify` | `TBC, re-verify` | After the fixes above. |

## Accepted residual

Findings outside the threat model in `CLAUDE.md`, recorded rather than fixed silently or
dropped. Each was demonstrated by the security gate. The first three rows need an adversary
who can commit to this repository or write to the build host during a build. Such an
adversary can edit `src/complyops/views/api.py` or substitute the artefact outright, so
hardening the packaging script against them is theatre rather than defence. The last two
rows are a different class and are recorded here for the same reason rather than that one:
the historical-probe row is a fact about history that no live control can change, and the
anchor row's adversary is a runtime writer on the persistent volume, already stated openly
in `SECURITY.md` and carried as an accreditation condition.

| Residual | Demonstrated | Why it is accepted |
| --- | --- | --- |
| A base64-encoded credential, and one inside a DEFLATE-compressed nested zip, pass the credential sweep | Tenth run, `2819cf5` | A pattern sweep over text cannot see a re-encoding. Recorded beside the sweep in `scripts/build-package.sh`. The sweep exists for an honest committer's paste, which is not encoded. |
| A quoted assignment split by an intervening comment passes both the sweep and the pre-write hook | Tenth run | Same class. Neither route crosses the comment text; recorded beside the sweep. |
| `verify-mode-check` and `verify-extra-file-check` survive deletion | Tenth run | Neither condition is reachable through `git archive`; a build under `umask 0111` did not strip the mode. Benign but unheld, and recorded as such rather than given a test that could not fail. |
| Two historical test probes in git history: a Privacy Enhanced Mail (PEM) private-key opening line at `330fb36`, and a file whose NAME carried the Amazon Web Services access-key-identifier shape at `24d93cc` | Tenth run | Neither carries key material; both were later assembled from parts, and neither is reachable from the current tree. No history rewrite warranted. Written here by description rather than by literal: writing either out in full makes this document refuse its own build. |
| The `find -type l` staged-symlink refusal and the `examined == 0` guard both survive deletion | Eleventh run | Each is shadowed by a control that fires first: the manifest's mode-120000 refusal catches a committed symlink, and the `git archive produced nothing` check catches an empty stage. Benign, and recorded rather than given a test that could not fail. |
| A volume writer can delete the anchor and its first-use marker together | Recorded since V2.1 | Stated openly in `SECURITY.md` and carried as an accreditation condition. |

## Open in scope

Not residual, and deliberately not in the table above: these are inside the threat model and
are open. They are here so the next reviewer scores them as known rather than as new. The
section has been wrong once by omission, which is why it now states what the rules match
before stating what they do not.

**What the content sweep matches.** An assignment at the start of a line, behind any run of
`ENV`, `ARG`, `export`, `-e`, `--env` or a list marker, at any indent, with an optional
opening quote or backtick; the same assignment anywhere in a line of prose, for an UPPER
case name, where "anywhere" means the character before the name need only be a non-word one,
so a query string and a bullet with no space after it are both caught; and a
credential-shaped token in any cell of a document table row whose name cell carries one of
these names. The keyword may be followed by more of the name, so `CLIENT_SECRET_V2=` is
caught. Case is folded everywhere except the prose rule.

Every figure below is pinned by `tests/test_sweep_cost_figures.py`, which re-runs each
experiment against the live rules and the live tree. Prose cannot hold a number: four of
these went stale, one of them written stale in the commit that measured it, and one file
contradicted itself about one experiment 154 lines apart. If a figure here disagrees with
that test, the test is right and this section is out of date.

**What it does not, and why each is left open.**

● `NAME = value` with spaces around the equals. Measured rather than assumed: allowing them
  gives 22 findings on 22 lines across all 157 tracked files at `1bdbdb8`, so the rule would
  fire on every build and be switched off within a week. The experiment is to replace `=`
  with `[ \t]*=[ \t]*` in that rule alone and scan every tracked file. The cost of closing
  it is a rule nobody keeps.
● A `name: value` mapping in YAML or JavaScript Object Notation (JSON), unquoted.
● A LOWER case name mid-line, such as `set client_secret=<value> in the console`. The prose
  rule is the one rule that does not fold case. Folding it gives 26 matches on 18 lines
  across all 157 tracked files, measured at `1bdbdb8`: 19 Python keyword arguments
  (`outgoing_key=`, `sort_keys=`) and 7 `sonar.projectKey=` lines in the skill templates,
  the latter admitted by the preceding-character widening made in the same commit. The
  anchored rule and the table rule both fold, so a lower-case name is caught in those two
  shapes and not in this one. This figure has been written three times and measured three
  ways, reading 23 and then 19 at earlier commits, each correct for an experiment nobody
  recorded. State the experiment, the scope and the commit with the number, or do not write
  the number.
● A name that BEGINS with one of the keywords, such as `SECRET_FOR_ENTRA=<value>`. The name
  must contain one of these words and have at least one character before it. Making that
  leading part optional gives 14 findings across the tracked tree, 9 of them in `src/`
  (eight `key_id=` and one `keys=`), at `1bdbdb8`. Left open at a measured price rather
  than bought.
● A table row carrying `[REDACTED:` or `TBC` ANYWHERE in it, in EITHER case, is skipped
  whole, because the rule folds case. That is a
  bypass for someone who adds `TBC` to a row on purpose, and it is the right trade: a
  cell-level exemption let the engine match a different cell instead, and the adversary
  this rule is for is an honest committer pasting a value into a table.
● The sweep is a pattern sweep over text. Base64 or any other re-encoding, and anything
  inside a compressed container, pass it. That limit is structural and is recorded beside
  the sweep as well as here.

## Deletion matrix

What the security gate measured when it deleted each control in `scripts/build-package.sh`
and `scripts/simulate-pipeline.sh` in turn and re-ran the packaging suite. A control that
survives deletion is one the next edit can silently undo, which is how the pointer race was
defeated three releases running. The probe sets differ between runs, so the counts are not
comparable across rows; the survivor names are. This table is the authoritative record; `docs/DEPLOYMENT.md`
points here rather than restating a figure, because restating it has been wrong three times.

| Run | Commit | Probed | Caught | Survivors that mattered |
| --- | --- | --- | --- | --- |
| Fourth | `533fa5c` | ~19 | 8 | Eleven build controls and both simulation guards, including three the same release had just added. |
| Sixth | `102df44` | 44 | 26 | The pointer `mktemp` fix, the simulation's red-suite guard, the coverage artefact assertion, the extra-file check. |
| Seventh | `ab16c1b` | 40 | 26 | The pointer private directory, the exemption match count, the coverage artefact guard, the `find -type l` refusal. |
| Eighth | `ef9c3f2` | 51 | 31 | The `mktemp -d` work directory, the `coverage.xml` guard, **six** of the nine sweep rules, the cleanup trap, the `find -type l` refusal. This row said eight of nine until the ninth run re-measured it at that commit: the AWS, generic and GitLab rules were already held by the filename and directory-name tests. Corrected here rather than left, because `docs/DEPLOYMENT.md` sends the reader to this table as the record that exists BECAUSE restating a figure in prose was wrong three times. |
| Ninth | `52f3e14` | 62 | 42 | The work directory's NAME beyond one literal and its MODE (a fixed `dist/.build.fixed`, and a `chmod 755`, both left the suite green), the `Bearer token` sweep rule, the cleanup trap, the `dist` symlink refusal. Sixteen further survivors are compensated by a control that fires earlier and are recorded as benign. |
| Tenth | `TBC, re-verify` | | | Tests were added after the ninth run for the work directory's mode and unpredictability, the trap under a signal, the `dist` refusal and the bearer rule; the matrix has not been re-run since. |

## V2.1

| Date | Gate | Commit | Verdict | What it found |
| --- | --- | --- | --- | --- |
| 2026-09-05 | `security-reviewer`, round twelve | `8af23a3` | **PASS** | The refusal row cap held under a 1.4 million window fuzz, eight end-to-end scenarios and concurrency. One MINOR on what the row-size pin measures, recorded beside the pin. |
| Rounds one to eleven | `security-reviewer` | various | **FAIL** each | Every round found something real and every finding was fixed and re-attacked. The cap was defeated twice after being declared bounded, and the flood residual figure was understated three times before it was measured at the serialised worst case. |
| `TBC, re-verify` | `engineering-reviewer` | `TBC, re-verify` | **PASS** recorded, artefact not in the tree | The verdict is referenced in the V2.1 history but no record was kept at the time. This file exists so that stops happening. |

## What these rows show

Every gate FAIL across V2.2 is a row above, and not one of them was in the application. The `amr` check
and the lockfile split were sound at the first pass, and the container needed only the
one-layer correction recorded above.

Most were in the machinery built to check the application, or in a document describing it:
a bill of materials pointed at the wrong tree, a test count asserted without measuring, a
lint gate observed only while skipping, and a correction applied to a summary but not to
the evidence beneath it, twice, in a record that ships. The pattern is worth naming, because
the temptation at each pass was to treat the finding as paperwork.

Two were not paperwork at all. The security gate found that the script deciding what leaves
this repository would ship a git-ignored `src/.env` inside a package stamped with a clean
commit, and would follow a symlink in an allowlisted directory and store whatever it pointed
at on the build host. Both were demonstrated, not theorised. A packaging script is
production code with a supply chain attached, and it had been treated as a convenience.

## How to add a row

Run the gate, then record the commit it ran against, the verdict verbatim, and the findings
in one sentence each. Do not record a verdict you did not see returned, and do not summarise
a FAIL as a PASS with caveats.
