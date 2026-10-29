# AI Security Lab

**Course:** cd15149 — LLM and Agentic AI Security

Every exercise in this course runs against the same fictional company, **Vantage Systems**,
and the same AI assistant, **Aria**. That continuity is deliberate: you attack Aria, then
you harden Aria, and by the end you have built up the same set of controls the course
project asks you to apply to a different agent.

See [`QUICK_START.md`](QUICK_START.md) to get running.

## The twelve skill pairs

All twelve are required.

| SP | Title | Target | What you build |
|----|-------|--------|----------------|
| SP01 | Reliable Prompt Injection Basics | vulnerable endpoint | evidence that injection works |
| SP02 | OWASP Audit of a Vulnerable LLM App | vulnerable endpoint | an OWASP-classified finding report |
| SP03 | Aria Indirect Injection | Aria | `block_injection()` |
| SP04 | Aria Defensive Prompting | Aria | a hardened system prompt |
| SP05 | Aria RAG Poisoning | Aria | `scan_for_injection()` |
| SP06 | Aria Agent Boundaries | Aria | `enforce_role()` |
| SP07 | Aria Logging and IR | Aria | `log_interaction()` |
| SP08 | Aria Human Risk Gates | Aria | `risk_gate()` |
| SP09 | Vulnerable Agent Task Hijacking | vulnerable agent | `validate_action()` |
| SP10 | Aria Multimodal Injection | Aria | `text_sanitizer()` |
| SP11 | Aria Named Guardrails | Aria | a named rule, `RULE-03` |
| SP12 | Agent Prompt Segregation | Aria | `chat_safe()` |

## Three targets, on purpose

A single model cannot be reliably vulnerable in the opening modules *and* serve as a
realistic agentic target later. So the course uses three:

- **A deliberately vulnerable HTTP endpoint** (SP01, SP02) — small model, weak by design,
  so early prompt injection lands every time and you can see the shape of the attack.
- **Aria** (SP03–SP08, SP10–SP12) — one-file exercises where you change a single function.
- **A local vulnerable agent** (SP09) — an agent loop that can be hijacked through its own
  data.

## How a skill pair is laid out

```
skill-pair-NN-slug/
  EXERCISE.md        what to do, and what "done" looks like
  DEMO.md            what the lesson video walks through
  starter/           the file you edit — one function, marked TODO
  solutions/         reference implementation and the reasoning behind it
  demo/              the vulnerable and fixed versions shown in the video
  data/              fixtures, where the exercise needs them
```

`demo/aria_vulnerable.py` is the starter with its stub left empty. `demo/aria_fixed.py` is
the same file with the stub filled in. They are one program in two states, which is exactly
what the lesson video shows you.

## Models

| Target | Model |
|--------|-------|
| Aria exercises | `qwen2.5:7b-instruct` |
| Vulnerable endpoint (SP01, SP02) | `qwen3:0.6b` |

Both are pre-pulled into the lab image. `OLLAMA_MODELS` points at `/voc/data/ollama/models`.

## Requirements

The exercises need Python 3 and `requests`. Nothing else. The heavier dependencies
(`chromadb`, `sentence-transformers`, `Pillow`) belong to the course project, and
`fastapi`/`uvicorn` to the vulnerable endpoint.
