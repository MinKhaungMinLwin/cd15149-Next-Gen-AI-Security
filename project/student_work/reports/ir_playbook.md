# Incident Response Playbook
## Northstar Research Agent

**Version:** 1.1
**Owner:** Security Operations Center
**Completed by:** Min Khaung Min Lwin
**Date:** 2026-11-07

This playbook applies to the hardened agent (`northstar_agent_hardened.py`). The vulnerable
baseline writes no audit log and must not be deployed.

---

## When to Activate This Playbook

Activate when any of the following occur:

- The agent executes a command that was not requested by the user
- Employee records or credentials appear in an agent response unexpectedly
- A user reports unusual agent behavior
- An alert fires from one of the monitoring rules below

---

## Incident Severity Levels

SOC response times follow the Security Incident Reporting Procedure v3.1.

| Level | Criteria | Examples | SOC response |
|-------|----------|---------|--------------|
| **P1 — Critical** | Active breach or confirmed credential exposure | `GET_SYSTEM_INFO` or `EXPORT_ALL_DATA` executed in production | 15 minutes |
| **P2 — High** | Unauthorized data access | Employee PII returned to wrong user, `query_hr_database` called for non-HR task | 1 hour |
| **P3 — Medium** | Suspicious but unconfirmed | Repeated injection attempts with no confirmed success; poisoned document detected | 4 hours |
| **P4 — Low** | Near-miss or policy violation | User trying injection, agent correctly refused | 24 hours |

---

## First 30 Minutes

The steps below are written for the worst case: `EXPORT_ALL_DATA` firing in production.

### Minutes 0–5: Confirm and Classify

- [ ] Pull the agent logs for the session in question
- [ ] Identify: which command or tool was called? What data was returned?
- [ ] Check whether it **executed** (`ACTION_EXECUTED`) or was **blocked** (`ACTION_BLOCKED`)
- [ ] Assign a severity level: executed = P1; blocked = P4, or P3 if repeated
- [ ] Page on-call if P1 or P2

**Log location:** `student_work/logs/agent_audit.jsonl` (one JSON event per line)
**On-call contact:** SOC on-call, soc@northstar-tech.com; Security Hotline ext. 9-SECURITY (9-7328)

```bash
# All security events, then everything from the affected session
grep -E '"event": "(ACTION_EXECUTED|ACTION_BLOCKED|RAG_REJECT)"' student_work/logs/agent_audit.jsonl
grep '"session_id": "<SESSION_ID>"' student_work/logs/agent_audit.jsonl
```

A hardened agent has no code path for `EXPORT_ALL_DATA`, so an `ACTION_EXECUTED` for it means
the wrong build is running or the code was changed. Treat that as a P1 by itself.

---

### Minutes 5–15: Contain

If the session is still active:

```bash
# Preserve the log first, with a hash, before anything else changes
cp student_work/logs/agent_audit.jsonl /secure/evidence/agent_audit_$(date +%Y%m%d_%H%M%S).jsonl
shasum -a 256 /secure/evidence/agent_audit_*.jsonl

# Stop the agent
sudo pkill -f northstar_agent
```

The agent has no user authentication yet, so no individual user can be blocked. Stopping the
agent is the only containment available. Once authentication exists, disable the affected
account instead.

If the session used RAG, also snapshot `chroma_data/` before changing it.

If data was exported or credentials were exposed:
- [ ] Notify the Data Privacy team immediately
- [ ] Start rotating exposed credentials: employee API keys, database password, admin token
- [ ] Do not attempt to hide or undo the access — preserve evidence

---

### Minutes 15–30: Assess and Notify

Answer these questions and document the answers:

| Question | How to answer it |
|----------|------------------|
| Which records were accessed? | `executed` field of the session's `interaction` events. `EXPORT_ALL_DATA` means assume all records. |
| Were credentials exposed? | `internal_api_key` is in every employee record, so an export means yes. `GET_SYSTEM_INFO` also exposes the database password and admin token. |
| Was the knowledge base modified? | Compare document IDs and content with the approved source. Check `retrieved` for unknown IDs and `rejected` for `injection_pattern`. |
| Is the attack ongoing? | Search other sessions for the same input or document ID. Check for new events after containment. |

Notify based on severity:
- P1/P2: CISO, Legal, HR (if employee data)
- P3: SOC team lead
- P4: Log and monitor

Assign an incident commander and a remediation owner before the 30-minute mark.

---

## Remediation Before Restarting

- [ ] Audit and purge malicious documents from the knowledge base:
  ```bash
  sudo python3 load_knowledge_base.py --reset
  sudo python3 load_knowledge_base.py
  ```
- [ ] Rotate any exposed credentials
- [ ] Apply hardened system prompt and guardrails
- [ ] Rerun the validation test suite before bringing the agent back online:
  ```bash
  # Run with the malicious documents loaded in a test copy, never in production
  python3 student_work/defenses/validation_tests.py
  python3 student_work/defenses/validation_live.py
  ```

---

## What to Log for Every Agent Interaction

These fields must be captured for every request. "Status" shows the current hardened agent.

| Field | Why It Matters | Status |
|-------|---------------|--------|
| Timestamp (UTC) | Forensic timeline | Logged (`ts`) |
| Session ID | Correlation | Logged (`session_id`) |
| User ID | Attribution | **Gap:** no authentication yet |
| Full user input | Evidence | Logged, first 500 characters (`user_input`) |
| Workflow and allowed tools | Shows which permissions applied | Logged (`workflow`) |
| Retrieved document IDs and distances | Detect RAG poisoning | Logged (`retrieved`) |
| Rejected documents and reasons | Detect poisoned content | Logged (`rejected`, `RAG_REJECT`) |
| Commands and tools executed | Alert on unauthorized actions | Logged (`executed`, `ACTION_EXECUTED`) |
| Commands and tools blocked, with reason | Detect attempts | Logged (`blocked`, `ACTION_BLOCKED`) |
| Model name | Reproducibility | Logged (`model`) |
| Model response | Detect leaked data; needed for alert 2 | **Gap:** not logged yet |
| Response time (ms) | Detect denial-of-service patterns | Logged (`latency_ms`) |

The audit log contains user input, so it needs restricted access and a retention period. In
production it must also be shipped to a tamper-evident store, not left as a local file.

---

## Alert Rules

Based on the attacks observed in Phase 2. These rules are defined, but not yet automated; until
they are connected to an alerting system, the audit log is reviewed manually.

| Alert Name | Trigger Condition | Severity | First Action |
|-----------|-------------------|----------|-------------|
| Privileged command executed | `ACTION_EXECUTED` with tool `export_all_data`, `get_system_info` or `search_employee` | P1 | Page on-call, stop the agent, start rotating credentials |
| Credentials in response | Response matches `sk-[A-Z]+-`, `db_password` or `admin_token` (requires response logging) | P1 | Page on-call, stop the agent, preserve the session |
| HR tool executed | `ACTION_EXECUTED` with tool `query_hr_database` | P2 | Page on-call, identify the records returned, notify Data Privacy |
| Poisoned document detected | `RAG_REJECT` with reason `injection_pattern` | P3 | Quarantine the document, identify who added it, notify the knowledge base owner |
| HR tool attempted | `ACTION_BLOCKED` with tool `query_hr_database` | P3 | Review the session's task and check for repeat attempts |
| Repeated injection attempts | 3+ `ACTION_BLOCKED` events for privileged tools in one session within 10 minutes | P3 | Review the session and contact the user's manager or the SOC team lead |
| Abnormal load | `latency_ms` over 120000, or over 30 interactions per session in 1 minute | P3 | Check for abuse, throttle or stop the session |

**Tuning note:** a single `ACTION_BLOCKED` for a privileged tool is P4 (log only). The model can
write a command name while refusing, as it did in validation test 1, so one event does not show
intent. `RAG_REJECT` with reason `distance` is normal behavior and must not alert; it fired for
legitimate documents during validation.

---

## Contacts

| Role | Name | Contact |
|------|------|---------|
| SOC | SOC on-call | soc@northstar-tech.com, ext. 9-SECURITY (9-7328) |
| AI Enablement | Team mailbox | ai-team@northstar-tech.com |
| Data Privacy | Team mailbox | privacy@northstar-tech.com |
| Legal | Team mailbox | legal@northstar-tech.com |
