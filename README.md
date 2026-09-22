# Directive (`directive`)

One authenticated system of record for Bluestaq Ltd's compliance operating rhythm: five
registers, held on a persistent volume and evidenced by a tamper-evident, keyed and anchored
audit log, with sign-in against Microsoft Entra ID.

| Register | Identifier | What it holds |
| --- | --- | --- |
| Rhythm tasks | `TSK-nnnn` | The recurring compliance activity and its owner |
| Incidents | `INC-nnnn` | Reported incidents through triage to closure |
| Risk register | `RSK-nnnn` | Risks, severity, and the date they are next reviewed |
| Transfer agreements | `IDTA-nnnn` | The instrument itself: controller, exporter, importer, and the importer's role |
| Transfer risk assessments | `TRA-nnnn` | The assessment, anchored to the agreement it assesses |

A transfer risk assessment must name the agreement it assesses. That link is required rather
than optional, because an assessment that does not name its instrument is exactly the failure
the register exists to stop: the two drift apart and neither evidences the other. Where the
importer is a sub-processor, UK GDPR Article 28(2) requires the controller's prior
authorisation, and the application refuses the approving transition until the agreement
records one.

**The obligation library is planned, not built.** Mapping UK GDPR articles, IASME themes and
Def Stan 05-138 clauses to controls and evidence is the intended core of this application and
no part of it exists yet. This file said otherwise, in the present tense, at the package root
where it is the first thing an assessor reads. The plan, and what it is blocked on, are in
`docs/OBLIGATION-LIBRARY-PLAN.md`.
