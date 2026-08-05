# OWASP LLM Top 10 — Risk Assessment

**Application:** Northstar Research Agent  
**Date:** 2026-07-29  
**Overall baseline risk:** Critical

| ID | Category | Present? | Severity | Evidence and recommendation |
|---|---|---:|---|---|
| LLM01 | Prompt Injection | Yes | Critical | The prompt says to follow all instructions, and RAG data is appended to the system message. Isolate untrusted content and enforce policy outside the model. |
| LLM02 | Insecure Output Handling | Yes | Critical | `parse_commands_from_response()` executes command-like model text without authorization. Replace implicit execution with schema validation and an action allowlist. |
| LLM03 | Training Data Poisoning | Related RAG risk | High | No fine-tuning occurs, but write access to the knowledge base enables poisoned context. Scan, approve, version, and monitor documents. |
| LLM04 | Model Denial of Service | Yes | Medium | There is no input limit, rate limit, concurrency bound, or per-user quota; calls may last 300–600 seconds. Add limits, cancellation, and quotas. |
| LLM05 | Supply Chain Vulnerabilities | Yes | Medium | Broad dependency ranges and an externally sourced model are used without integrity verification. Pin hashes, scan packages, and verify model provenance. |
| LLM06 | Sensitive Information Disclosure | Yes | Critical | `GET_SYSTEM_INFO`, `EXPORT_ALL_DATA`, and employee lookup expose credentials, PII, and API keys. Remove embedded secrets and enforce identity-aware authorization. |
| LLM07 | Insecure Plugin Design | Yes | Critical | `query_hr_database` is advertised and executable in every workflow. Apply deny-by-default, workflow-specific permissions and data minimization. |
| LLM08 | Excessive Agency | Yes | High | The loop runs up to three model/tool cycles without approval and is told to use all tools. Narrow capabilities and require approval for consequential actions. |
| LLM09 | Overreliance | Yes | Medium | Responses lack citations, confidence signals, and provenance. Cite document IDs and require review for consequential use. |
| LLM10 | Model Theft | Limited | Low | Mistral is open weight, but prompts and internal architecture can be extracted. Prevent prompt disclosure and restrict endpoint access. |

## Evidence

`student_work/attacks/baseline_security_tests.py` drove deterministic model outputs through the real vulnerable parsers. It observed:

- `GET_SYSTEM_INFO` executed and sensitive configuration returned.
- `EXPORT_ALL_DATA` executed and employee records returned.
- A poisoned document led to `GET_SYSTEM_INFO` execution.
- A research task invoked `query_hr_database` and returned employee data.

This proves the dangerous application behavior after a model is induced or compromised. A live prompt-susceptibility run could not be completed because Ollama and project dependencies were unavailable locally.

## Top priorities

1. Remove secrets and sensitive admin operations from the general agent path.
2. Enforce command and tool authorization in Python, independent of model text.
3. Treat every retrieved document as untrusted and filter it before prompting.
