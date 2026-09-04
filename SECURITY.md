# Security

## Reporting a vulnerability

Report a suspected vulnerability in the Bluestaq Compliance Operations Console
(`comply-ops`) to **dpa@bluestaq.uk**, under the **Bluestaq Vulnerability Disclosure
Policy (POL-006)**. That address reaches the UK Information Security Manager, who is the
named owner for this application.

Please do not open a public issue for a security report, and please do not test against
the production deployment. Include what you did, what you observed, and what you expected;
a proof of concept helps and is not required.

Required by AMD-001 section 10.6.

## Scope

● The application source in this repository.
● The container image built from the `Dockerfile` at the repository root.
● The deployed instance at `comply-ops.apps.bluestaq.com`.

Out of scope: the Bluestaq App Store platform itself, Microsoft Entra ID, and Microsoft
365, each of which is reported to its own owner.

## What this application defends

The primary asset is **audit log integrity**, because the log is the evidence shown to an
IASME or Defence Cyber Certification assessor and, if it comes to it, to the Information
Commissioner's Office. The audit chain is keyed with HMAC-SHA256 under a server-held key
and anchored to a record of where the log should end, so **write access to the stored log
alone is not enough to rewrite history undetected**: an edit, a re-stamp, a reorder, a
deletion, a truncation and a wholesale replacement are all caught.

Write access to the storage VOLUME is a different matter, and the two limits below are
real. Do not read the sentence above as covering them.

Two limits are stated openly rather than left for a reader to discover:

● An actor with write access to the persistent volume can delete the anchor and its
  first-use marker together, which leaves a state indistinguishable from a fresh install.
● The same actor, holding no key, can restore a genuine older anchor alongside a matching
  truncation of the log. The refusal to move backwards is held in memory PER PROCESS, and
  a restart clears it, which on this platform is routine. The result is worse than the case
  above: it does not look like a missing anchor, it looks like clean shorter history, and
  verification positively certifies it as intact. From V2.1 the container runs a single
  worker, so a second process no longer accepts the rolled-back anchor without a restart;
  that narrows the window and does not close the gap.

  Closing both needs corroboration against a store that actor does not control, which for
  this build is the exported evidence pack. That detects the removal of entries a prior
  pack recorded, once the export module and a written comparison step exist; neither does
  yet. See `docs/DEPLOYMENT.md`.
● Container runtime properties (non-root execution, absence of a package manager, absence
  of setuid bits) are verified by construction in the `Dockerfile` and by a post-build
  probe recorded in `docs/DEPLOYMENT.md`. They are not verified by the test suite.

## Supported versions

The deployed release is the supported release. There is no back-porting: fixes land on
the current version and are deployed.
