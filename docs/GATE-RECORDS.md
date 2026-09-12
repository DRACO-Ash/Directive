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
| 2026-09-11 | `security-reviewer`, thirteenth run | `6d9394f` | **FAIL** | Four MAJORs. The hook's BEHAVIOUR was held by no test: leaving its rule array untouched and iterating only its first element stopped twelve of thirteen rules blocking with every parity test green, because the parity test compares rule text and nothing executed the hook. `ssh-keygen -t ed25519` writes an extensionless file that neither `*.pem` nor `*.key` matches, so an OpenSSH private key was still trackable. And two figures in shipped documents were not supported: 23 keyword arguments against 19 measured, and a tracked-file count one short of the tree. |
| 2026-09-11 | `security-reviewer`, fourteenth run | `72ab2d0` | **FAIL** | Three MAJORs. The hook was blinded again, this time by narrowing WHAT it reads rather than which rules it runs: every probe reached it through `tool_input.content`, so cutting `new_string`, `file_text` and the `edits` loop left all twenty-one tests green while every `Edit` and `MultiEdit` write stopped being scanned. Eight of the eleven filename patterns could be deleted with the suite green, because one test probed one name. And two cost figures in shipped files were unsupported. |
| 2026-09-11 | `engineering-reviewer`, seventh pass | `72ab2d0` | **FAIL** | Three MAJORs, all three shared with the run above or its consequence: the five filename patterns added in that delta were held by no test; "eleven of twelve rules" was twelve of thirteen; and the leading-part cost figure read 12 where 9 findings in `src/` is measurable, eight of them `key_id=`. It also confirmed the hook-execution tests hold the rule set, and that the two former skips cannot flake. |
| 2026-09-11 | `security-reviewer`, fifteenth run | `1bdbdb8` | **FAIL** | Three MAJORs. The hook was defeated a THIRD way, by a dimension the previous two rounds did not cover: what the rules see. A one-line `file_path` carve-out exempting `.env` passed all twenty-seven tests while letting a client secret into `.env.production`, and a `.slice(0, 400)` let a credential past 400 bytes into any document, because every probe was a short single line with no path. The registration test asserted the substring `secret-scan`, so pointing both files at a hook that does not exist was green. And a fourth cost figure was stale in two shipped documents and in the sweep, which contradicted itself about one experiment 154 lines apart. |
| 2026-09-11 | `engineering-reviewer`, eighth pass | `1bdbdb8` | **FAIL** | Four MAJORs, three of them created by the delta under review. A count written stale in the commit that grew the list it counted; the same fourth figure; the filename mirror drifting in the ADD direction, where a pattern with no probe was green; and a `pytest.skip` reintroduced forty lines below the comment condemning the one it removed. It confirmed by mutation that the sweep, the hook's reach and the rule set are all genuinely held. |
| 2026-09-11 | `security-reviewer`, sixteenth run | `e89e18d` | **FAIL** | Three MAJORs. The hook was retired by one `rm`: this module's skip condition was keyed on the hook itself, so deleting it skipped all thirty-six tests including the two written to catch that, and the suite exited 0. The figure pinning was half a fix: the MEASUREMENT could no longer drift, the PROSE reporting it still could, demonstrated by rewriting 22 to 47 and 26 to 99 in all three documents with the suite green. And the tracked-file count was stale in `CHANGELOG.md`, unanchored, in the commit that changed it. |
| 2026-09-11 | `engineering-reviewer`, ninth pass | `e89e18d` | **FAIL** | Three MAJORs, two shared with the run above. The third was the new cost-figure module hardcoding `/usr/bin/git` with a guard that only reads the return code, so on any image that puts git elsewhere it raises rather than skips: five errors at the platform's test stage, a failed upload and every later stage skipped. Every other module in the suite resolves a tool with `shutil.which`. |
| 2026-09-11 | `security-reviewer`, seventeenth run | `7a7a642` | **FAIL** | Two MAJORs, both the figure class narrowed rather than closed for the third pass running. The clauses INSIDE a pinned sentence were free, so the Python keyword-argument count and the sonar split could be set to anything with the suite green, and one of them is the very figure this table records as wrong at the thirteenth run. And the sweep read three declared files, so false figures placed in `README.md` and in the accreditation record, both of which ship, were never read. |
| 2026-09-11 | `engineering-reviewer`, tenth pass | `7a7a642` | **FAIL** | Two MAJORs, one shared. The other: the previous pass's `NotebookEdit` fix added the field to the house-voice hook's payload list but not to its tool gate, so it was unreachable for exactly the tool it was added for and the hook still exited 0 on every notebook write, with a comment beside it claiming the fix. Nothing in the suite referenced that hook at all, which is why it shipped broken. |
| 2026-09-11 | `security-reviewer`, eighteenth run | `f5ebd2f` | **FAIL** | One BLOCKER and two MAJORs. The loop was RED at the commit: the tracked-file count read 159 against a 160-file tree, because the loop measures before the commit and the figure describes after, and the new test file was untracked when it ran. That is the count going stale for the third time, in the commit written to stop it. Markdown emphasis also hid a digit from the scanner, so a false section in `README.md` shipped green, and a breakdown clause reworded away was caught by nothing. |
| 2026-09-11 | `engineering-reviewer`, eleventh pass | `f5ebd2f` | **FAIL** | Two BLOCKERs and five MAJORs, the BLOCKERs shared with the run above. Also: the remainder of the sonar split was unpinned, so the sentence could contradict itself with nothing red; the house-voice hook's `Bash` branch was carved out of its own matcher check and held by nothing, and it is the only enforcement anywhere of the `+` rule; and this file's pointer for the test count resolved to rows that carried none. |
| 2026-09-11 | `security-reviewer`, nineteenth run | `d2293e6` | **FAIL** | One MAJOR. This release note pointed an assessor at gate rows for a test count and a coverage figure that no row carries, and the previous commit had made that claim BROADER while purporting to fix it. Plus a strikethrough digit the emphasis stripper did not know, one character from the class it had just closed. The loop, the package digest and the simulation all reproduced, and six credential shapes behaved exactly as the open-gap record says. |
| 2026-09-11 | `engineering-reviewer`, twelfth pass | `d2293e6` | **FAIL** | Three MAJORs. The live-cost figure was turned from a word into a digit and wired to nothing, so rewriting 1 to 0 was green while the bullet beside it claimed every figure was asserted. Emphasis was stripped only where it touched a digit, so `**47 findings**` stayed invisible. And the module written to stop stale counts carried two in its own docstring. |
| 2026-09-11 | `security-reviewer`, twentieth run | `5f3c4cf` | **FAIL** | Two MAJORs, one of them a REGRESSION against the previous commit. Widening the emphasis stripper to remove backticks made four of the eleven shapes unmatchable, because those four still carried backticks themselves, so the sweep went silently blind to a whole canonical sentence and three clauses and a false figure shipped green in the accreditation record. Underscore emphasis was invisible too, one character beyond the class the same commit had closed. |
| 2026-09-11 | `engineering-reviewer`, thirteenth pass | `5f3c4cf` | **FAIL** | Three MAJORs, the regression shared. Also: the release note's claim that every figure in it is read back was false for six of them, in the fourth wrong version of that sentence and the second where the fix broadened what it was fixing; and two documents stated that the wider stripper closed the gap when for four shapes it opened one. |
| 2026-09-11 | `engineering-reviewer`, fourteenth pass | `84e80ed` | **PASS** | Five MINORs, including the two below, and no MAJOR. The first engineering PASS of this release. It verified the claim that had been false at four consecutive passes, by scripting a check that every test name cited in a shipped document resolves to a real test, and searched all 81 commits to confirm no false figure was ever committed. Two of them: a per-shape assertion weakened by a shorter sibling matching first, and four shapes backing no declared figure and held by nothing. |
| 2026-09-12 | `security-reviewer`, twenty-first run | `84e80ed` | **FAIL** | One MAJOR, the same one the pass above raised as a MINOR and scored harder here. Deleting three entries from the shape set left the suite green while a false figure sailed into the accreditation record: the set is parametrised over, so a deleted entry is simply not tested, and four of the shapes exist only to ban a wording this project has retired, so nothing else misses them. Twenty-three injection probes, including fullwidth digits and a line-broken number, were all caught. |
| 2026-09-12 | `security-reviewer`, twenty-second run | `e787043` | **FAIL** | One MAJOR. The scanner was blinded through the stage ABOVE the shape set: every assertion in the module normalises both sides of its comparison, so all of them are symmetric and none can see the normaliser itself weaken. With the emphasis stripper disabled and nothing else changed, four false figures shipped into the accreditation record and the release note with the whole suite green. Thirteen injection probes against the intact scanner were all caught, including fullwidth digits and a line-broken number. |
| 2026-09-12 | `engineering-reviewer`, fifteenth pass | `e787043` | **FAIL** | Two MAJORs. The test named for banning a phrasing asserted only that the scanner could READ it, so a phrasing carrying a measured number would be read and then allowed, and the property survived its own falsification. And the figure for the previous round's deletion was the UNMUTATED pass count attached to a mutated run. It also measured that the frozen shape copy holds ORDER rather than membership, which the comment beside it got wrong. |
| 2026-09-12 | `security-reviewer`, twenty-third run | `e07434d` | **FAIL** | Two MAJORs. The ban assertion compared the WHOLE phrasing while the sweep judges the matched substring, so a phrasing whose match was an allowed figure passed the test named for banning it. And this sweep's own comment claimed every figure in the file was re-measured, in a file the accreditation record sends an assessor to, while a line count in a note four lines below it was free to be anything. |
| 2026-09-12 | `engineering-reviewer`, sixteenth pass | `e07434d` | **FAIL** | Two MAJORs. The asymmetric leg added to hold the emphasis stripper was retired by one invisible line: neutering the fixture left it asserting what every other test already asserted. And a comment counted four unbacked shapes five lines from an assertion deriving two, in the module whose purpose is that prose cannot hold a number. It judged the module past the point where its own complexity is the risk, on the evidence that both MAJORs were false sentences rather than wrong code. |
| 2026-09-12 | `security-reviewer`, twenty-fourth run | `3b4fb54` | **FAIL** | Two MAJORs. The guard added the round before closed the INSTANCE and not the class: a fixture returning the marker prepended to the phrasing satisfied a presence check while leaving every digit bare, and with the stripper then disabled a false figure shipped green. And the ban assertion read the alternation's leftmost match, so a decoy clause earlier in a phrasing became the match and the shape under test was never judged. Of fifteen injection probes against the live sweep, fourteen were refused and one shipped, that one being the recorded open limit. |
| 2026-09-12 | `engineering-reviewer`, seventeenth pass | `3b4fb54` | **FAIL** | One MAJOR, shared: two experiment figures written as WORDS sat outside the carve-out of a sentence claiming every experiment figure in the block was re-measured, in a file the accreditation record sends an assessor to. Both gates were asked for a deletion plan rather than more findings, and both gave one. |
| 2026-09-12 | `security-reviewer`, twenty-fifth run | `221d5ef` | **FAIL** | One MAJOR and one MINOR, both shared with the pass below: a docstring and this record pointed a maintainer at a test the same commit had deleted, and the justification for keeping the shape anchor was stated generally where it holds narrowly. It withdrew its own twenty-fourth-run recommendation to delete that anchor, on measurement. Its attacks on the live sweep, the audit chain, the route gating and the container rules all held. |
| 2026-09-12 | `engineering-reviewer`, eighteenth pass | `221d5ef` | **FAIL** | Two MAJORs, the dangling citation and the over-stated anchor justification, measured exhaustively across all fifteen shapes. It judged the test set minimal on measurement and proposed the structural answer to the class that has produced every MAJOR for five rounds: make a named test reference machine-checkable rather than auditing it by eye. |
| 2026-09-12 | `security-reviewer`, twenty-sixth run | `e944c1d` | **FAIL** | One MAJOR and three MINORs. The citation guard added that commit could not read the node-id form the deployment runbook actually uses, so renaming the test it cites left the whole suite green with an assessor-facing document pointing at nothing. Its exception was keyed by name and applied everywhere while its own comment justified it by path. And it demonstrated that the packaging sweep reads only the STAGED package, a limit recorded nowhere. Eighteen credential probes, six control deletions and thirteen identity-token attacks all held. |
| 2026-09-12 | `engineering-reviewer`, nineteenth pass | `e944c1d` | **FAIL** | Three MAJORs: the same node-id gap, a measured figure written as ten where seven is measurable, and a false justification for parsing test names rather than collecting them. It measured parsed against collected at 568 to 568 and judged the new module under-scoped rather than over-built. |
| 2026-09-12 | `engineering-reviewer`, twentieth pass | `0d26da5` | **PASS** | Five MINORs, no MAJOR. It ran a sharper mutant than the fix was written against, repointing the node id at a wrong but EXISTING module so the bare name still resolved elsewhere, and reproduced the defect on the parent commit to show the justification was measured both ways. It confirmed the shared reader's only dangerous coupling, an empty corpus, reddens on both sides, and judged the citation module still under its useful size. |
| 2026-09-12 | `security-reviewer`, twenty-seventh run | `0d26da5` | not completed | The container hosting this session restarted before the run reported. Recorded rather than omitted, because a gate that did not finish is not a gate that passed. The tree was verified intact afterwards: clean, matching the remote, and every `@auth.required` present. Re-run at `1537b62`, recorded in the pending row at the foot of this table. |
| 2026-09-12 | `security-reviewer`, twenty-seventh run | `1537b62` | **FAIL** | Two MAJORs, and the first findings in the APPLICATION since the third run. Route gating was held by a hand-written four-path list and nothing read the route map, so a new ungated route served every register to an anonymous caller with the suite count unchanged byte for byte. And deleting `USER 10001:10001` from the Dockerfile shipped a root container with no test, lint leg or packaging gate noticing, against a hard rule. Twenty other control deletions were all red. |
| 2026-09-12 | `engineering-reviewer`, twenty-first pass | `1537b62` | **FAIL** | One MAJOR: the span scan added the previous commit skipped its own file with an inline comparison, and widening that to every path under `tests/` excluded every shipped test module with the suite green, which is the identical defect the sibling module already records and closes eight lines away. It also corrected its own method mid-review, having stacked a flag that suppressed the very count it was reading. |
| 2026-09-12 | `security-reviewer`, twenty-eighth run | `9b3bba3` | **FAIL** | One MAJOR and one MINOR. The route-map walk added at `1537b62` keyed its public set by PATH alone, so the exemption on a declared path covered every METHOD of it: an ungated `@api_bp.post("/diagnostics")` rode in on the read-out's GET exemption and served every register to an anonymous caller, with the suite unchanged at 1028 passed and 2 skipped. It asked for the sibling check to compare `(method, rule.rule)` pairs so a renamed public method is red too. And it asked for the quoted rule's missing `key|keys` price to be recorded separately from the 22 measured for the unquoted rule. |
| 2026-09-12 | `engineering-reviewer`, twenty-second pass | `9b3bba3` | **FAIL** | Three MAJORs and two MINORs, one MAJOR shared with the run above. The Dockerfile checks read a raw `splitlines()` while the shipped stage writes its `ENV` across continuation lines, so `PORT=` and `DATA_DIR=` added in that form were invisible to the very test written to catch them. The flood-sizing assertion accepted the daily MiB alone as a substitute for the whole sentence, leaving `719 KiB` and the 288 windows free in the file that states them. The `USER` check did not strip its line, so `  USER root` passed, and the window period was typed rather than derived from `WINDOW_SECONDS`. It named six completeness assertions the fix had to satisfy. |
| 2026-09-12 | `engineering-reviewer`, twenty-third pass | `bbe2322` | **FAIL** | Three MAJORs and three MINORs, every one in prose rather than code. It re-measured all eight mutation claims and found them true, then found the sentences around them wrong: this record attributed the quoted-rule request to a security run it had never recorded, the comment on `SPELLED_MINUTES` said both carriers write the period where only the deployment record does, and the decomposition of the new 7 was unheld, so rewriting `All six ... in auth.py, csrf.py and views/auth_routes.py` into a self-contradicting sentence naming two modules that carry none of the findings left the whole suite green. The missing rows are the two above, added with the fix as every prior round did. |
| 2026-09-12 | `security-reviewer`, twenty-ninth run | `bbe2322` | **PASS** | Three MINORs, no MAJOR, and the first security PASS since the application findings at `1537b62`. It probed every rule in the map under both postures with eight methods, forged five identity headers and a session cookie, flooded `/auth/callback` from 3000 addresses in one window and measured exactly 500 rows on the volume, and wrote line separators, a right-to-left override, a NUL and a quote-break into a user agent, finding no byte above 0x7F in the log and the chain intact. It reproduced the run-28 finding against the fix and got a red. Its own finding: the public exemption was applied BEFORE the endpoint assertion, so a second `GET /api/diagnostics` registered ahead of `health_bp` shadowed the read-out and served the credential presence map to an anonymous caller with both tests green. Fixed by reordering, and the reproduction is now red. |
| 2026-09-12 | `security-reviewer`, thirtieth run | `ac3d4ea` | **PASS** | Two MINORs, no MAJOR, and it re-broke a control added the same day. The module-name check bounded its window at 400 characters, so appending the false sentence "Two of the six sit in `store.py` and `config.py`" past that window left the positive half finding the true names, the negative half never seeing the false ones, and the suite green: the exact defect shape the test was written to close. The window is now bounded at the passage, the comment block or the bullet, rather than at a character count. It also showed an ungated `HEAD /api/leak` returning its data in a response header was walked by nothing, because the walk subtracts `HEAD` from every method set; the docstring stated that exclusion honestly and no test held the claim. Both closed and both mutations red. Its own attacks held throughout: nine gated routes, five spoofed identity headers, six path variants, four volume tampers each failing closed, nine injection shapes, and a planted `CLIENT_SECRET` in `.env.example` failing the build. |
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
| Test probes in git history, including a Privacy Enhanced Mail (PEM) private-key opening line at `330fb36` and a file whose NAME carried the Amazon Web Services access-key-identifier shape at `24d93cc` | Tenth run, re-swept at the nineteenth | None carries key material. A sweep of every blob in history surfaces more than the two named here, all of them earlier spellings of this suite's own probes before they were assembled from parts; the row named two because two is what the gate that wrote it had found, which is why it now says what the sweep finds rather than a count. No history rewrite warranted. Written by description rather than by literal: writing either out in full makes this document refuse its own build. |
| The `find -type l` staged-symlink refusal and the `examined == 0` guard both survive deletion | Eleventh run | Each is shadowed by a control that fires first: the manifest's mode-120000 refusal catches a committed symlink, and the `git archive produced nothing` check catches an empty stage. Benign, and recorded rather than given a test that could not fail. |
| A volume writer can delete the anchor and its first-use marker together | Recorded since V2.1 | Stated openly in `SECURITY.md` and carried as an accreditation condition. |

## A disagreement between the gates, recorded rather than resolved silently

The twenty-fourth security run recommended deleting `FROZEN_SHAPES` on the ground that
membership is held twice without it. The seventeenth engineering pass measured the case that
recommendation does not cover, and both gates have since re-measured it across all fifteen
shapes: for the two that are substrings of a longer sibling, deleting from `_SHAPES` and
`PHRASINGS` together is red at that anchor and nowhere else. For the other thirteen another
test is red as well. The twenty-fifth security run withdrew its recommendation on that
measurement. The anchor is kept on the engineering gate's
measurement, and its docstring now states that narrower reason rather than the order claim
it carried before. Both gates agreed on everything else they proposed cutting, and that was
done: a self-consistency test measured redundant under the exact defeat it was written for,
and the layer of prose that described what OTHER parts of the module hold, which is where
every finding of the last four rounds landed.

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

Every LIVE figure in the list of open limits below is pinned by
`tests/test_sweep_cost_figures.py`, which re-runs each
experiment against the live rules and the live tree, asserts that each sentence and each
clause inside it is still SAID where it belongs, and sweeps EVERY tracked file for anything
written in the same shapes. Three parts, and each was added only after the previous two were
defeated: a clause with a wrong number, a clause reworded away, and a digit wrapped in
markdown emphasis, which renders to a reader as a number and was invisible to a scanner
anchored on a bare digit. Emphasis is stripped everywhere rather than only where it touches
a digit, because the narrower form left `**47 findings**` readable to a person and invisible
to the scanner, and backtick, asterisk, tilde and underscore are all stripped.

Be exact about what that cost, because the widening reopened a larger hole than it closed:
stripping backticks from the text while four of the shapes still contained backticks made
those four unmatchable, and a false figure of that shape shipped green in the accreditation
record. The shapes are written once as templates and compiled through the same normalisation
the text goes through, so the two agree by construction, and each shape is exercised
against its own phrasing, so a stripper change that makes a shape unreadable is red there.
That is the assertion to keep whenever the stripper changes; it is what nothing checked. All three parts, because every earlier attempt closed one and left the next
open: pinning the measurement left the prose free, and a reviewer rewrote 22 to 47 and 26 to
99 in three documents with the suite green; pinning three named files left every other
shipped document free, and a reviewer put false figures in `README.md` and in the
accreditation record; and pinning whole sentences left the clauses inside them free, so 19
became 31 and a figure written as the word "eight" became "twelve", which is the exact
defect this table records at the thirteenth run. Every figure the module reads back is a digit, so the sweep
can read it.

Prose cannot hold a number on its own. Six went stale before this, one written stale in the
commit that measured it, and one file contradicted itself about one experiment 154 lines
apart. No commit hash is cited with any figure below, deliberately: a hash is one more thing
to go stale, and a red test is a better anchor than a citation. The rows in the table above
narrate figures that were WRONG at the time, which is their purpose, and they are written so
that no sweep mistakes them for a live measurement.

**What it does not, and why each is left open.**

● `NAME = value` with spaces around the equals. Measured rather than assumed: allowing them
  gives 22 findings on 22 lines across every tracked file, so the rule would fire on
  every build and be switched off within a week. The experiment is to replace `=`
  with `[ \t]*=[ \t]*` in that rule alone and scan every tracked file. The cost of closing
  it is a rule nobody keeps.
● A `name: value` mapping in YAML or JavaScript Object Notation (JSON), unquoted.
● A LOWER case name mid-line, such as `set client_secret=<value> in the console`. The prose
  rule is the one rule that does not fold case. Folding it gives 26 matches on 18 lines
  across every tracked file: 19 Python keyword arguments (`outgoing_key=`, `sort_keys=`)
  and 7 `sonar.projectKey=` lines, 6 of them in the skill templates and 1 in this project's
  own `sonar-project.properties`, all admitted by the preceding-character widening. The
  anchored rule and the table rule both fold, so a lower-case name is caught in those two
  shapes and not in this one. This figure has been written several times and measured
  several ways, each correct for an experiment nobody recorded, and the earlier values are
  narrated in the table above rather than repeated here, where a sweep would read them as
  live. State the experiment and the scope with the number, and let the test hold both.
● A name that BEGINS with one of the keywords, such as `SECRET_FOR_ENTRA=<value>`. The name
  must contain one of these words and have at least one character before it. Making that
  leading part optional gives 14 findings across the tracked tree, 9 of them in `src/`, of
  which 8 are `key_id=` and 1 is `keys=`. Left open at a measured price rather
  than bought.
● A bare `key` or `keys` in the QUOTED rule's keyword group, so `key = "<value>"` in source
  is not caught by it. The unquoted rule's group carries both words and the quoted rule's
  does not, and the difference had no price against it until the twenty-eighth security run
  and the twenty-second engineering pass, both at `9b3bba3` and both recorded in the table
  above, asked for one. Measured separately from the 22 above, because it is a different
  rule and a different widening: adding them gives 7 findings on 7 lines across every
  tracked file, 6 beyond the declared double the shipped rules already report, every one a
  session key NAME rather than a value, in `auth.py`, `csrf.py` and `auth_routes.py`. Those
  three module names are derived from the scan and asserted; the count is not restated as a
  word, because a word figure is invisible to any scanner. The experiment is to add
  `key|keys` to that rule's group alone and scan every tracked file.
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
