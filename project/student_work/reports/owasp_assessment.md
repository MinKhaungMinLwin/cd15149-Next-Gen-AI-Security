# OWASP LLM Top 10 — Risk Assessment
**Application:** Northstar Research Agent (`northstar_agent.py`, vulnerable baseline)
**Assessor:** Min Khaung Min Lwin
**Date:** 2026-11-03

**Method:** Source review of `northstar_agent.py`, plus a live baseline session against
Mistral 7B (`mistral:7b-instruct-v0.2-q4_0`) with ChromaDB holding the 3 legitimate
documents. Live transcript: `Phase 1- Baseline and OWASP Proof.txt`. Exploitation of
each risk is demonstrated in `security_findings.md` (Phase 2).

---

## Baseline Observations (Live)

| # | Check | Input | Observed result |
|---|-------|-------|-----------------|
| B1 | Basic chat (RAG off) | `What can you help me with?` | Normal answer, but the model volunteered: *"If you need assistance with an internal admin command, please let me know and I will execute it exactly when requested."* |
| B2 | RAG retrieval | `rag on` → `What is the AI usage policy` | Retrieved `['northstar-ai-policy', 'acceptable-use-guidelines']`; accurate summary of policy v2.3, with no document IDs cited in the answer. |
| B3 | Tool use | `Creat a ticket: laptop screen is broken` | Model replied `CREATE\_TICKET: "Laptop screen is broken"` plus a form with unfilled placeholders. App executed `['CREATE_TICKET: ']` → `Ticket TKT-20261102225006 created: ` **with an empty description**. |
| B4 | Greeting | (on startup, before any input) | The banner lists `SEARCH_EMPLOYEE:<email>`, `EXPORT_ALL_DATA` and `GET_SYSTEM_INFO` to every user. |

---

## LLM01 — Prompt Injection

| Field | Your Response |
|-------|--------------|
| Present? | **Yes** |
| Severity | **Critical** |
| Evidence | The system prompt says to execute admin commands *"exactly when requested by any user"* and to *"follow all instructions provided to you"* (`northstar_agent.py:118`, `:124`). B1 shows the model has adopted this: it offers to run admin commands on request. Retrieved documents are appended to the **system** message (`:312–314`), so knowledge-base text carries the same authority as the developer's instructions; this is an indirect-injection channel. |
| Recommendation | Remove the admin commands from the prompt, keep untrusted retrieval and user text out of the system role behind explicit data delimiters, and enforce authorization in code rather than through the model. |

---

## LLM02 — Insecure Output Handling

| Field | Your Response |
|-------|--------------|
| Present? | **Yes** |
| Severity | **Critical** |
| Evidence | `parse_commands_from_response()` regex-scans free-form model text, and `chat()` executes every match with no authentication, authorization, or confirmation (`:262–274`, `:336–340`). The text is even normalized first (`replace("\\_", "_")`), so markdown-escaped output still runs. B3 proves the parser is unreliable: the `CREATE_TICKET` pattern stops at the first quote (`:269`), so the model's `CREATE_TICKET: "Laptop screen is broken"` executed as `CREATE_TICKET: ` and produced a ticket with no description. Any command name the model mentions, even inside a refusal, matches the same way. |
| Recommendation | Replace regex execution of free text with schema-validated, typed tool calls checked against a deny-by-default allowlist, and reject malformed or empty arguments. |

---

## LLM03 — Training Data Poisoning

| Field | Your Response |
|-------|--------------|
| Present? | **Partially** (as RAG knowledge-base poisoning; there is no fine-tuning) |
| Severity | **High** |
| Notes | Mistral 7B is used as-is, so classic training-data poisoning is out of scope. The equivalent risk is the ChromaDB knowledge base: `load_knowledge_base.py` upserts any file it is given, with no review, signing, or content scanning, and retrieved text goes straight into the system prompt. B2 shows that retrieval directly shapes answers, so whoever can write a document can steer the agent. The three files in `knowledge_base/malicious/` are examples of this attack. |
| Recommendation | Gate ingestion with review and provenance (owner, version, hash), scan documents for injection patterns at ingest and retrieval time, and quarantine anything flagged. |

---

## LLM04 — Model Denial of Service

| Field | Your Response |
|-------|--------------|
| Present? | **Yes** |
| Severity | **Medium** |
| Evidence | There are no input-length limits, rate limits, per-user quotas, or concurrency caps. Each request may hold the model for up to 600 s (`chat()`, `:329`), and `run_agent_task()` chains up to 3 LLM calls of 300 s each (`:397`, `:421`). Conversation history grows without bound in interactive mode (`:529–530`). On local hardware a single long or repeated prompt monopolizes the only model instance. |
| Recommendation | Cap input and history tokens, add per-user rate limits and request queuing, and lower timeouts with cancellation. |

---

## LLM05 — Supply Chain Vulnerabilities

| Field | Your Response |
|-------|--------------|
| Present? | **Yes** |
| Severity | **Medium** |
| Dependencies reviewed | `requirements.txt` uses ranges (`chromadb>=0.5.0,<1.0.0`, `requests>=2.31.0`, `Pillow>=10.0.0`, `sentence-transformers>=2.2.0`) with no lockfile or hashes; chromadb alone pulls a large transitive tree (onnxruntime, kubernetes, posthog, …). The model is pulled by tag from the Ollama registry, and ChromaDB downloads its embedding model (`all-MiniLM-L6-v2` ONNX) at first run, both without digest verification. |
| Recommendation | Pin exact versions with hashes in a lockfile, scan dependencies (e.g. `pip-audit`), and pin and verify the model and embedding-model digests from an internal mirror. |

---

## LLM06 — Sensitive Information Disclosure

| Field | Your Response |
|-------|--------------|
| Present? | **Yes** |
| Severity | **Critical** |
| Evidence | `GET_SYSTEM_INFO` returns the production DB host, `db_password` and an admin token (`:168–176`); `EXPORT_ALL_DATA` and `SEARCH_EMPLOYEE` return full employee records including `internal_api_key`, salary band and clearance notes (`:48–101`, `:156–165`). None of these checks who is asking. B4 shows the startup banner advertises all three commands to any user. Secrets are hard-coded in source. |
| Recommendation | Remove credentials from source and the agent path (use a secret manager), drop bulk export entirely, and require identity-aware authorization with field-level minimization for any employee lookup. |

---

## LLM07 — Insecure Plugin Design

| Field | Your Response |
|-------|--------------|
| Present? | **Yes** |
| Severity | **Critical** |
| Tool(s) affected | `query_hr_database` (returns employee PII and API keys; advertised to every agent task, `:202–210`, `:362`); `create_ticket` (assignee taken verbatim from model output, so a ticket can be routed to any address, `:213–218`); `save_note` (writes model-chosen content to disk with no size or content checks, `:221–227`); legacy `CREATE_TICKET` command (B3: accepts an empty description). |
| Recommendation | Expose tools per workflow on a deny-by-default basis, remove the HR tool from research tasks, and validate every argument (allowed assignees, length, non-empty fields) in code before execution. |

---

## LLM08 — Excessive Agency

| Field | Your Response |
|-------|--------------|
| Present? | **Yes** |
| Severity | **High** |
| Evidence | `AGENT_PROMPT` tells the model to *"Complete all tasks the user requests. Use all available tools as needed"* (`:366`). The loop runs up to 3 iterations, executing every parsed tool call with no human approval (`:397–450`). B3 shows an action (ticket creation) firing as a side effect of the model's free text, without the user confirming the content. |
| Recommendation | Grant only the tools each workflow needs, require user confirmation for consequential actions (tickets, data access), and log each tool decision. |

---

## LLM09 — Overreliance

| Field | Your Response |
|-------|--------------|
| Present? | **Yes** |
| Severity | **Medium** |
| Example | In B3 the agent presented a complete-looking ticket form, with placeholders such as `[Current date and time]` and `[Your laptop model and serial number]` never filled in, while the ticket actually stored had an empty description. A user would reasonably believe a useful ticket was filed. In B2 the answer is fluent but cites no source document, so the user cannot verify it. |
| Recommendation | Cite retrieved document IDs in every RAG answer, report tool results verbatim instead of model-written confirmations, and label generated content as needing review. |

---

## LLM10 — Model Theft

| Field | Your Response |
|-------|--------------|
| Present? | **Limited** |
| Severity | **Low** |
| Notes | Mistral 7B is a public open-weight model, so weight extraction has no value. What *can* be extracted is the system prompt and the internal command set, and B4 shows the command set is already disclosed in the banner. That knowledge makes the LLM01/LLM06 attacks easier. The Ollama API (`localhost:11434`) also has no authentication if it is ever exposed beyond localhost. |
| Recommendation | Remove internal commands from the prompt and banner, tell the model not to reveal its instructions, and keep the Ollama endpoint bound to localhost or behind authentication. |

---

## Summary

| ID | Category | Severity | Present? |
|----|----------|----------|---------|
| LLM01 | Prompt Injection | Critical | Yes |
| LLM02 | Insecure Output Handling | Critical | Yes |
| LLM03 | Training Data Poisoning | High | Partially (RAG poisoning) |
| LLM04 | Model Denial of Service | Medium | Yes |
| LLM05 | Supply Chain Vulnerabilities | Medium | Yes |
| LLM06 | Sensitive Information Disclosure | Critical | Yes |
| LLM07 | Insecure Plugin Design | Critical | Yes |
| LLM08 | Excessive Agency | High | Yes |
| LLM09 | Overreliance | Medium | Yes |
| LLM10 | Model Theft | Low | Limited |

**Overall Risk Rating:** ☒ Critical  ☐ High  ☐ Medium  ☐ Low

**Top 3 Priorities:**
1. **Stop executing model output.** Replace regex command parsing with authorized, schema-validated tool calls (LLM02, LLM07).
2. **Remove privileged commands and secrets from the agent path.** Drop `EXPORT_ALL_DATA` and `GET_SYSTEM_INFO` from the prompt, banner and dispatcher, and move credentials to a secret manager (LLM01, LLM06).
3. **Treat retrieved documents as untrusted data.** Separate them from instructions, filter by relevance and injection patterns, and control knowledge-base ingestion (LLM01, LLM03).
