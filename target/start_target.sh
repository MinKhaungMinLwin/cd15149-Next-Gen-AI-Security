#!/usr/bin/env bash
set -euo pipefail

export OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://localhost:11434}"
export OLLAMA_MODEL="${OLLAMA_MODEL:-qwen3:0.6b}"
export SECRET_KEY="${SECRET_KEY:-FLAG{pr0mpt_1nj3ct10n_vuln3r4bl3_3ndp01nt}}"

exec python3 chatbot_api.py
