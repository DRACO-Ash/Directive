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
| 2026-09-10 | both gates, re-run | `TBC, re-verify` | `TBC, re-verify` | After the fixes above. |

## V2.1

| Date | Gate | Commit | Verdict | What it found |
| --- | --- | --- | --- | --- |
| 2026-09-05 | `security-reviewer`, round twelve | `8af23a3` | **PASS** | The refusal row cap held under a 1.4 million window fuzz, eight end-to-end scenarios and concurrency. One MINOR on what the row-size pin measures, recorded beside the pin. |
| Rounds one to eleven | `security-reviewer` | various | **FAIL** each | Every round found something real and every finding was fixed and re-attacked. The cap was defeated twice after being declared bounded, and the flood residual figure was understated three times before it was measured at the serialised worst case. |
| `TBC, re-verify` | `engineering-reviewer` | `TBC, re-verify` | **PASS** recorded, artefact not in the tree | The verdict is referenced in the V2.1 history but no record was kept at the time. This file exists so that stops happening. |

## What these rows show

Five gate FAILs across V2.2, and not one of them was in the application. The `amr` check
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
