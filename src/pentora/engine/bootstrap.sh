#!/usr/bin/env bash
# Artifex reactive engine - Colab (Ubuntu, Tesla T4, ~15GB VRAM) bootstrap for local Ollama.
# Run this in a Colab cell prefixed with ! or %%bash. Installs Ollama, serves it, pulls the
# model, and runs the strict-JSON smoke test.
set -euo pipefail

# Verify the exact tag at https://ollama.com/library/qwen3.5/tags before relying on :9b.
# Known-good fallbacks that fit a T4: qwen3:8b, qwen3:14b (Q4), qwen2.5-coder:7b.
MODEL="${MODEL:-qwen3.5:9b}"

echo "[*] installing ollama"
curl -fsSL https://ollama.com/install.sh | sh

echo "[*] starting server in the background"
nohup ollama serve > /tmp/ollama.log 2>&1 &
sleep 5

echo "[*] pulling ${MODEL} (first pull downloads several GB)"
if ! ollama pull "${MODEL}"; then
  echo "[!] '${MODEL}' not found on the registry - falling back to qwen3:8b"
  MODEL="qwen3:8b"
  ollama pull "${MODEL}"
fi

ollama list

echo "[*] strict-JSON smoke test via the engine client"
MODEL="${MODEL}" python3 -c "from pentora.engine.ollama_client import smoke_test; import os; print(smoke_test(os.environ['MODEL']))"

echo "[OK] local AI layer ready: ${MODEL}"
