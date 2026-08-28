# Policy source documents

The two documents this application is built against are **not held in this repository**.
They are Bluestaq Ltd internal policy instruments and they live in the policy library, not
in application source control.

| Reference | Document | Governs |
| --- | --- | --- |
| AUD-001 | Audit and Monitoring Policy addendum, Compliance Operations Console application audit controls. Addendum to POL-001 section 11 and Handbook B.14. | What the audit log captures, its integrity, retention and review. |
| AMD-001 | Information Security Policy amendment, Compliance Operations Console. Amendment to POL-001. | Change control, accreditation, and the Secure Development Lifecycle in section 10.6. |

Both are prepared by Ash Higgins, Information Security Manager and Data Protection Lead,
and approved by Adam Field, Managing Director. Both carry an unsigned approval row: Adam
Field's date is blank on each at the time of writing, so they are treated as binding on
this build while the signature is outstanding. `TBC, re-verify` before the accreditation
review.

Ask the Information Security Manager for the current versions. Do not copy them back into
this repository, and do not paste extracts into an issue, a pull request description or a
commit message.

## Why they are referenced rather than held

The application is not classified; these documents are Bluestaq Ltd internal instruments
with their own classification and their own review cycle. Vendoring them here conflated the
two, put a document under a lifecycle that is not its own, and meant a policy revision
needed an application commit to take effect.

Referencing them costs one thing and it is worth naming: the conformance table in
`../DEPLOYMENT.md` can no longer be audited against a copy sitting beside it. A reader
checking a row now needs the document from the library. That is the correct trade, because
the alternative was a stale copy that reads as authoritative.

## How the conformance table stays honest without them

`../DEPLOYMENT.md` cites clauses by reference, not by quotation: "AUD-001, old and new
value of a changed field", "AMD-001 section 10.6". Each row names the clause, states what
this build does, and says plainly whether that meets it, exceeds it, or deviates from it.
An assessor reads the row beside the document, which is how they would work anyway.

Every deviation is recorded for the Managing Director's sign-off rather than argued away.
The list is in `../DEPLOYMENT.md`.
