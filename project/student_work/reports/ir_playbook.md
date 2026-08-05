# Incident Response Playbook — Northstar Research Agent

**Version:** 1.0  
**Owner:** Security Operations Center  
**Date:** 2026-07-29

## Activation and severity

Activate for unexpected command/tool execution, sensitive data in a response, suspicious retrieved content, or a monitoring alert.

| Priority | Criteria |
|---|---|
| P1 Critical | Confirmed credential disclosure, `GET_SYSTEM_INFO`, or `EXPORT_ALL_DATA` |
| P2 High | Unauthorized PII/HR access or successful tool-policy bypass |
| P3 Medium | Repeated injection or poisoned-document detection without disclosure |
| P4 Low | Single blocked policy violation |

## First 30 minutes after `EXPORT_ALL_DATA`

### Minutes 0–5 — confirm and classify

- Page SOC on-call and declare P1.
- Preserve the interaction, gateway, tool, retrieval, identity, and network logs.
- Identify session/user IDs, records returned, recipients, and active sessions.
- Record timestamps and evidence hashes; do not edit original evidence.

### Minutes 5–15 — contain

- Disable the export capability at the policy/tool gateway.
- Revoke the affected session and temporarily disable the agent if bypass persists.
- Block the malicious document or user only after preserving evidence.
- Rotate exposed credentials and revoke exposed API keys/tokens.
- Notify the privacy lead; do not attempt to conceal or delete access evidence.

### Minutes 15–30 — assess and notify

- Determine exactly which records and secrets left the trust boundary.
- Search correlated sessions for the same prompt, document, command, or destination.
- Notify the CISO, Legal, Privacy, and HR; start required breach-assessment clocks.
- Assign incident commander, communications owner, and remediation owner.

Restart only after malicious content is removed, exposed credentials are rotated, the cause is fixed, and the validation suite passes in a clean environment.

## Required interaction log fields

- UTC timestamp, request ID, user ID, session ID, authenticated role
- Full user input or privacy-preserving secured reference
- Model/version, system-prompt version, workflow classification
- Retrieved document IDs, versions, distances, rejection reasons
- Proposed, blocked, and executed commands/tools with authorization decision
- Sanitized tool arguments/results and data classification
- Response, latency, token/iteration counts, outcome, policy version
- Source IP/device and correlation/trace ID

Logs must be access-controlled, tamper-evident, encrypted, retention-governed, and scrubbed of reusable secrets.

## Alert rules

| Alert | Trigger | Severity | First action |
|---|---|---|---|
| Bulk export | Any proposed or executed `EXPORT_ALL_DATA` | P1 if executed; P3 if blocked | Page on-call or preserve blocked attempt |
| System secret access | `GET_SYSTEM_INFO` or credential pattern in output | P1 | Disable session and rotate secrets |
| HR privilege violation | `query_hr_database` outside authorized HR workflow | P2 | Block tool and inspect session |
| Poisoned retrieval | Document rejected for injection pattern | P3 | Quarantine document and notify KB owner |
| Repeated injection | Three blocked command/injection events per user in 10 minutes | P3 | Rate-limit and investigate |
| Authorization mismatch | Proposed tool not in workflow allowlist | P2 | Block and inspect policy classification |
| Unusual retrieval | High rejection rate or new malicious document across sessions | P2 | Pause ingestion source and scope exposure |

## Evidence and recovery checklist

- Preserve prompts, responses, retrieved-document versions, tool decisions, and identity logs.
- Reset and reload only approved knowledge-base content.
- Rotate all exposed secrets and invalidate sessions.
- Patch the root cause and conduct peer review.
- Run security and functional validation, then monitor a staged restart.
- Complete lessons learned and update detections within five business days.

## Contacts

| Role | Contact |
|---|---|
| SOC | soc@northstar-tech.com |
| AI Enablement | ai-team@northstar-tech.com |
| Data Privacy | privacy@northstar-tech.com |
| Legal | legal@northstar-tech.com |
