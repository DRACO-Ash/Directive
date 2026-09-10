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
| 2026-09-10 | `engineering-reviewer` | `c4a33cf` | **FAIL** | Two MAJORs. The Continuous Integration dependency scan and software bill of materials still targeted `requirements.txt` after the lockfile split, so the artefact described 15 components against the 8 the image carries and the shipping tree was scanned nowhere in Continuous Integration. And `CHANGELOG.md` asserted "790 tests", a figure measured at neither commit it covered. Six MINORs. The `amr` check, the split and the packaging scripts were mutation-proven sound. |
| 2026-09-10 | `engineering-reviewer`, re-run | `TBC, re-verify` | `TBC, re-verify` | After the fixes above. |

## V2.1

| Date | Gate | Commit | Verdict | What it found |
| --- | --- | --- | --- | --- |
| 2026-09-05 | `security-reviewer`, round twelve | `8af23a3` | **PASS** | The refusal row cap held under a 1.4 million window fuzz, eight end-to-end scenarios and concurrency. One MINOR on what the row-size pin measures, recorded beside the pin. |
| Rounds one to eleven | `security-reviewer` | various | **FAIL** each | Every round found something real and every finding was fixed and re-attacked. The cap was defeated twice after being declared bounded, and the flood residual figure was understated three times before it was measured at the serialised worst case. |
| `TBC, re-verify` | `engineering-reviewer` | `TBC, re-verify` | **PASS** recorded, artefact not in the tree | The verdict is referenced in the V2.1 history but no record was kept at the time. This file exists so that stops happening. |

## How to add a row

Run the gate, then record the commit it ran against, the verdict verbatim, and the findings
in one sentence each. Do not record a verdict you did not see returned, and do not summarise
a FAIL as a PASS with caveats.
