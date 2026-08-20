# Security

## Reporting a vulnerability

Report a suspected vulnerability in the Bluestaq Compliance Operations Console
(`comply-ops`) under the **Bluestaq Vulnerability Disclosure Policy (POL-006)**. Contact
the UK Information Security Manager (ISM), who is the named owner for this application.

`TBC, re-verify`: this file needs the POL-006 reporting address or link before the first
deploy. It is deliberately absent rather than guessed, because inventing a contact address
is exactly the kind of plausible fabrication that gets a security report sent nowhere.

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
and anchored to a record of where the log should end, so neither write access to the log
nor access to the storage volume alone is enough to rewrite history undetected.

Two limits are stated openly rather than left for a reader to discover:

● An actor with write access to the persistent volume can delete the anchor and its
  first-use marker together, which leaves a state indistinguishable from a fresh install.
● The same actor, holding no key, can restore a genuine older anchor alongside a matching
  truncation of the log. The in-process refusal to move backwards does not survive a
  restart, and restarts are routine on this platform, so the result is worse than the
  case above: it does not look like a missing anchor, it looks like clean shorter history,
  and verification positively certifies it as intact.

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
