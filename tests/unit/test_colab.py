"""Colab bridge: setup script + valid notebook generation (pure stdlib, no engine deps)."""
from __future__ import annotations

import json
from pathlib import Path

from pentora.engine.colab import build_notebook, setup_script, write_notebook


def test_setup_script_installs_mitmproxy_and_boots_ollama() -> None:
    s = setup_script(model="qwen3:8b")
    assert "mitmproxy" in s
    assert "ollama serve" in s
    assert "ollama pull qwen3:8b" in s
    assert s.startswith("#!/usr/bin/env bash")


def test_build_notebook_is_valid_nbformat() -> None:
    nb = build_notebook(target="https://app.acme.com", model="qwen3:8b")
    assert nb["nbformat"] == 4
    assert isinstance(nb["cells"], list) and len(nb["cells"]) >= 2
    all_src = "".join("".join(c["source"]) for c in nb["cells"])
    assert "from pentora.engine.app import start" in all_src
    assert "https://app.acme.com" in all_src
    assert "qwen3:8b" in all_src


def test_write_notebook_roundtrips(tmp_path: Path) -> None:
    out = write_notebook(tmp_path / "cart.ipynb", target="https://x.io", model="qwen3:14b")
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["nbformat"] == 4
    assert any("qwen3:14b" in "".join(c["source"]) for c in doc["cells"])
