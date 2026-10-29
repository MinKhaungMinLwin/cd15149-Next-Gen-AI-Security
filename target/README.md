# Vulnerable LLM Endpoint

This is the Course 3 opening target for:

- `SP01`
- `SP02`

It preserves the same intentionally vulnerable endpoint concept as the original containerized project, but runs as a plain local Python service instead of Docker.

## Why This Exists

The course design for the opening modules is still correct:

- students should attack a deliberately weak endpoint
- the target should expose a simple `/chat` API
- the system prompt should contain a secret that can leak through prompt injection

The only thing that changed is orchestration. Instead of Docker, this version runs directly on the host with a local virtual environment and Ollama.

## Prerequisites

- Python 3.12 or 3.13
- Ollama running locally on `http://localhost:11434`
- the `mistral:7b-instruct-v0.2-q2_K` model available in Ollama

## Quick Start

```bash
cd /voc/startercode/course_materials/target
./setup_target.sh
./start_target.sh
```

In another terminal:

```bash
./check_target.sh
```

Expected URL:

`http://localhost:8000`

## Course 3 Usage

Once the health check passes:

```bash
cd /voc/startercode/course_materials/exercises
python3 scripts/run_sp.py SP01
python3 scripts/run_sp.py SP02
```

## Stop

Use `Ctrl+C` in the terminal running `./start_target.sh`.
