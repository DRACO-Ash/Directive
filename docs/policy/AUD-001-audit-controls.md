# BLUESTAQ LTD - Audit and Monitoring Policy

## Addendum: Compliance Operations Console Application Audit Controls

**COMMERCIAL IN CONFIDENCE**

| Field | Value |
| --- | --- |
| Policy Reference | POL-001 Section 11 (Monitoring) / Handbook B.14 |
| Addendum Number | AUD-001 |
| Classification | COMMERCIAL IN CONFIDENCE |
| Prepared By | Ash Higgins, ISM and DPL |
| Approved By | Adam Field, Managing Director |

## ADDENDUM: Application Audit and Monitoring Controls

This addendum defines the audit logging, monitoring, and review requirements for the
Compliance Operations Console (comply-ops). It supplements the existing monitoring
provisions in POL-001 Section 11 and Handbook B.14.

## Audit Log Scope

The Compliance Operations Console generates application-level audit logs capturing every
user interaction that creates, modifies, or deletes compliance data. These logs are
written to a dedicated SharePoint List (lst-AuditLog) within the uk-infosec-compliance
site, ensuring they inherit the site's sensitivity label and DLP policies.

The following events are logged:

| Event Category | Events Captured | Data Recorded |
| --- | --- | --- |
| Authentication | Login, logout, failed login, session expiry | Timestamp, UPN, IP address, user agent, success/failure |
| Task management | Task viewed, task completed, task status changed, task note added | Timestamp, user, task ID, old status, new status |
| Incident management | Incident created, incident updated, incident phase changed, ICO notification triggered | Timestamp, user, incident ref, field changed, old/new value |
| Register operations | Asset/risk/SIP/supplier record created, updated, or archived | Timestamp, user, record type, record ID, fields changed |
| Form submissions | Incident form, access change form, DSAR form, supplier form submitted | Timestamp, user, form type, key field values |
| Audit export | Evidence pack exported for IASME theme | Timestamp, user, theme selected, export format |
| Administration | Role mapping changed, configuration updated | Timestamp, user, setting changed, old/new value |

## Log Integrity

● Audit logs are write-once from the application's perspective. The app creates list
  items; it does not update or delete them. Modification and deletion of audit log items
  in SharePoint requires ISC-Owners (MD) permission.
● Each log entry includes a SHA-256 hash of the event data (timestamp + user + action +
  resource), providing tamper detection.
● SharePoint list versioning is enabled on lst-AuditLog, retaining all versions of every
  item.

## Log Retention

Audit logs are retained for a minimum of 24 months in the active lst-AuditLog list. After
24 months, logs are archived to Library 08 (Archive) as annual CSV exports and retained
for the six-year minimum per Handbook Annex A.8. The active list is pruned annually to
maintain query performance.

## Log Review

| Review Activity | Frequency | Owner | Task Reference |
| --- | --- | --- | --- |
| Review application audit log for anomalous access patterns | Weekly | ISM | W-01 (scope expanded) |
| Review failed login attempts and session anomalies | Weekly | ISM | W-02 (scope expanded) |
| Review Application Insights for errors and performance degradation | Weekly | ISM | W-03 (scope expanded) |
| Full audit log analysis, access patterns, data modification trends, export activity | Monthly | ISM | M-05 (scope expanded) |
| Audit log integrity check (hash verification on sample) | Quarterly | ISM | Q-06 (scope expanded) |

## Monitoring and Alerting

Azure Application Insights provides real-time monitoring of the Compliance Operations
Console. The following alerts are configured:

| Alert | Condition | Severity | Notification |
| --- | --- | --- | --- |
| Application down | Zero successful requests for 5 minutes | Critical | Teams Adaptive Card to ISM |
| High error rate | More than 5% of requests returning 5xx in a 10-minute window | High | Teams Adaptive Card to ISM |
| Authentication failure spike | More than 10 failed logins in a 5-minute window | High | Teams Adaptive Card to ISM and MD |
| Slow response | p95 response time over 5 seconds for 10 minutes | Medium | Teams Adaptive Card to ISM |
| Dependency vulnerability | Dependabot or safety detects Critical or High CVE | High | GitHub notification to ISM |

## Evidence for Assessors

The audit logging and monitoring controls provide evidence for the following IASME
clauses:

| IASME Clause | Evidence Provided |
| --- | --- |
| 12.1 (Audit logging) | lst-AuditLog with timestamped, user-attributed records of all data access and modification |
| 12.3 (Time synchronisation) | All timestamps in UTC from Azure App Service (NTP-synchronised) |
| 12.5 (Monitoring) | Application Insights dashboards, alert configuration, weekly review notes |
| 12.9 (Vulnerability management) | CI/CD security scan results, Dependabot PR history, pen test inclusion |
| 14.5 (Incident detection) | Authentication failure alerts, error rate alerts, anomalous access pattern detection |

| Action | Name | Role | Date |
| --- | --- | --- | --- |
| Prepared by | Ash Higgins | ISM and DPL | April 2026 |
| Approved by | Adam Field | Managing Director | |
