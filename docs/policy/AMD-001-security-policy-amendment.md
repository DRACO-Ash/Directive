# BLUESTAQ LTD - Information Security Policy

## Amendment Notice: Compliance Operations Console (Python Application)

**COMMERCIAL IN CONFIDENCE**

| Field | Value |
| --- | --- |
| Policy Reference | POL-001, Information Security Policy |
| Amendment Number | AMD-001 |
| Effective Date | Upon MD approval |
| Classification | COMMERCIAL IN CONFIDENCE |
| Prepared By | Ash Higgins, ISM |
| Approved By | Adam Field, Managing Director |

## AMENDMENT: POL-001 Security Policy Amendments

The following amendments to the Information Security Policy (POL-001) are required to
cover the deployment of the Compliance Operations Console, a Python and Flask web
application hosted on Azure App Service.

## Section 10: Change Management

### 10.3 SYSTEM CHANGE CONTROL, ADDITION

For internally developed applications maintained in source control (Git), the System
Change Control process is satisfied by: (a) all changes committed to a version-controlled
repository with descriptive commit messages, (b) changes to the production branch require
a pull request reviewed and approved by a designated reviewer, (c) automated CI/CD checks
(linting, security scanning, unit tests) must pass before merge, (d) deployment to
production requires explicit approval in the CI/CD pipeline. The UK Information Security
Officer retains authority to approve or reject changes. Where the ISM is also the
developer, this dual-role exception is documented in OPS-002 (R-007) and mitigated by
automated security checks and MD oversight.

### 10.4 ACCREDITATION, ADDITION

All internally developed applications must undergo a security review by the UK Information
Security Officer prior to production deployment. The review must confirm: authentication
via Entra ID with MFA, authorisation enforcing least-privilege, secure storage of secrets
(Azure Key Vault or equivalent), encrypted communications (TLS 1.2 or above), input
validation and output encoding, dependency vulnerability scanning, and inclusion in the
annual penetration test scope. The accreditation decision is recorded and retained as
evidence in Library 04.

### 10.5 SOFTWARE MANAGEMENT, ADDITION

The Compliance Operations Console (comply-ops) is added to the approved software allow
list. The application is internally developed, hosted on Azure App Service, and maintained
via the bluestaq-uk/comply-ops GitHub repository. Python dependency updates are managed
via Dependabot automated pull requests and are subject to the same patching SLAs as
operating system and firmware updates (Handbook B.10).

## Section 11: Secure Business Operations

### 11.1 MONITORING, ADDITION

Azure Application Insights telemetry for the Compliance Operations Console is included in
the weekly security log review (task W-01). Application-level audit logs (lst-AuditLog
SharePoint List) recording user logins, data modifications, and form submissions are
reviewed weekly and retained for 12 months per Handbook B.14.

### 11.4 VULNERABILITY SCANNING, ADDITION

The Compliance Operations Console (comply-ops.bluestaq.uk) is included in the monthly
vulnerability scan scope (task M-01). Automated dependency vulnerability scanning is
performed on every code change via the CI/CD pipeline (safety and Dependabot). Findings
are triaged and remediated per the standard patch SLAs.

### 11.5 PENETRATION TESTING, ADDITION

The Compliance Operations Console is included in the scope of the annual external
penetration test (task A-04) from the first test cycle (September 2026). The test scope
includes: authentication bypass, authorisation escalation, injection attacks, session
management, API security (Graph API token handling), and infrastructure configuration.

## New Section: Secure Development

### 10.6 SECURE DEVELOPMENT LIFECYCLE

Where Bluestaq develops internal applications, the following Secure Development Lifecycle
(SDLC) controls apply:

● All source code is stored in a private, access-controlled repository with branch
  protection and audit logging.
● Security static analysis (SAST) is performed automatically on every code change using
  industry-standard tools.
● Third-party dependencies are pinned to specific versions with integrity verification.
  Automated vulnerability scanning identifies known CVEs in dependencies.
● Secrets and credentials are never stored in source code, environment variables, or
  configuration files. All secrets are retrieved at runtime from a secure vault service.
● Input validation is applied to all user-supplied data. Output encoding prevents
  cross-site scripting. CSRF tokens protect state-changing requests.
● Security headers (Content-Security-Policy, Strict-Transport-Security,
  X-Content-Type-Options, X-Frame-Options) are applied to all responses.
● Applications are tested against the OWASP Top 10 before production deployment and
  annually thereafter.
● A SECURITY.md file in the repository links to the Bluestaq Vulnerability Disclosure
  Policy (POL-006) for responsible disclosure.

| Action | Name | Role | Date |
| --- | --- | --- | --- |
| Prepared by | Ash Higgins | ISM and DPL | April 2026 |
| Approved by | Adam Field | Managing Director | |
