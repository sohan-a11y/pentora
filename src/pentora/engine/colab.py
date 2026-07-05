"""Google Colab deployment bridge — generate a ready-to-run notebook + the Ubuntu setup script.

    from pentora.engine.colab import write_notebook
    write_notebook("pentora_cart.ipynb", target="https://app.example.com", model=DEFAULT_MODEL)

The generated notebook: cell 1 sets up the Ubuntu environment (installs mitmproxy, installs and
boots a background Ollama server, pulls the model); cell 2 runs the engine via the one-call facade.
Pure stdlib — importable without the optional playbook deps.

For a richer, verified walkthrough (self-contained demo, no external target needed), see the
pre-built ``colab/pentora_cart_colab.ipynb`` in the repo instead of generating one from scratch.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# An uncensored community fine-tune of Qwen3.5-9B (Apache-2.0, GGUF on Hugging Face). The LLM here
# only classifies a captured transaction into a vulnerability category (JSON, temperature 0) to
# route playbooks — it never mints a finding (see docs/cart-engine.md §1) — so this narrow,
# authorized-testing use case is a reasonable fit. Safety-tuned base models sometimes refuse or
# hedge on "does this look exploitable" framing even for benign, authorized security classification,
# which shows up as false negatives. Pass any other Ollama tag via ``model=`` to use something else.
DEFAULT_MODEL = "hf.co/HauhauCS/Qwen3.5-9B-Uncensored-HauhauCS-Aggressive:Q4_K_M"
_FALLBACK_MODEL = "qwen3.5:9b"                            # stock model if the primary pull fails


def setup_commands(model: str = DEFAULT_MODEL) -> list[str]:
    """Shell commands to prepare the Colab (Ubuntu) environment."""
    return [
        "pip -q install 'pentora[engine,capture]' mitmproxy py-trees pydantic httpx",
        "apt-get -qq install -y zstd || (apt-get -qq update && apt-get -qq install -y zstd)",
        "curl -fsSL https://ollama.com/install.sh | sh",
        "nohup ollama serve > /tmp/ollama.log 2>&1 &",
        "sleep 5",
        f"ollama pull {model} || ollama pull {_FALLBACK_MODEL}",
    ]


def setup_script(model: str = DEFAULT_MODEL) -> str:
    """The setup as a runnable bash script (verify the model tag at ollama.com/library)."""
    return "#!/usr/bin/env bash\nset -euo pipefail\n" + "\n".join(setup_commands(model)) + "\n"


def _code_cell(src: str) -> dict[str, Any]:
    return {
        "cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
        "source": src.splitlines(keepends=True),
    }


def _md_cell(src: str) -> dict[str, Any]:
    return {"cell_type": "markdown", "metadata": {}, "source": src.splitlines(keepends=True)}


def build_notebook(
    target: str = "https://app.example.com", model: str = DEFAULT_MODEL
) -> dict[str, Any]:
    setup = "\n".join(f"!{c}" for c in setup_commands(model))
    run = (
        "from pentora.engine.app import start\n"
        f"e = start(target={target!r}, model={model!r})\n"
        "\n"
        "# Feed captured traffic: a HAR export from DevTools, or route a browser via mitmproxy.\n"
        "# e.ingest_har('traffic.har')\n"
        "\n"
        "summary = e.run()\n"
        "print(summary)\n"
        "print(e.report_markdown('pentora-cart-report.md'))"
    )
    return {
        "cells": [
            _md_cell(
                "# Pentora CART — Colab runner\n\n"
                "Autonomous capture -> chain -> validate -> report, on a local Ollama model. "
                "No data leaves this VM."
            ),
            _md_cell("## 1. Environment — mitmproxy + local Ollama"),
            _code_cell(setup),
            _md_cell("## 2. Run the engine"),
            _code_cell(run),
        ],
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python"},
            "accelerator": "GPU",
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }


def write_notebook(
    path: str | Path, target: str = "https://app.example.com", model: str = DEFAULT_MODEL
) -> Path:
    p = Path(path)
    p.write_text(json.dumps(build_notebook(target, model), indent=1), encoding="utf-8")
    return p
