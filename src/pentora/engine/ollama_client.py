"""Local Ollama classifier — strict JSON, temperature 0. The engine's routing/intent brain.

Uses only stdlib ``urllib`` (zero extra deps) so it runs anywhere the engine core runs. Points
at a native Ollama server (``ollama serve``) — in Artifex's setup, inside Colab on the T4. The
model NEVER free-writes attacks: it classifies, routes, and extracts structured intent at
``temperature: 0`` with ``format: json``. Concrete payloads come from the RAG oracle instead.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Any

DEFAULT_HOST = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen3.5:9b"   # verify at https://ollama.com/library/qwen3.5/tags


class OllamaClassifier:
    def __init__(
        self, model: str = DEFAULT_MODEL, host: str = DEFAULT_HOST, timeout: float = 120.0
    ) -> None:
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = timeout

    def alive(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.host}/api/tags", timeout=10) as r:  # noqa: S310
                return bool(r.status == 200)
        except Exception:  # noqa: BLE001
            return False

    def classify(self, system: str, user: str) -> dict[str, Any]:
        """Return the model's JSON object. Raises on transport/JSON error."""
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(  # noqa: S310 - localhost Ollama, trusted scheme
            f"{self.host}/api/chat", data=data, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            body = json.loads(resp.read().decode())
        content = body.get("message", {}).get("content", "{}")
        result: dict[str, Any] = json.loads(content)
        return result


def smoke_test(model: str = DEFAULT_MODEL, host: str = DEFAULT_HOST) -> dict[str, Any]:
    """Verify the local socket + strict-JSON classification. Used by bootstrap.sh."""
    clf = OllamaClassifier(model=model, host=host)
    if not clf.alive():
        raise RuntimeError(f"Ollama not reachable at {host} — is `ollama serve` running?")
    return clf.classify(
        system=(
            "You are a strict classifier. Given an HTTP response, output JSON "
            '{"leaked_data": true|false, "reason": "<=10 words"}. No prose.'
        ),
        user='HTTP 200 body: {"user":"victim@x.com","ssn":"***"}',
    )


if __name__ == "__main__":
    print(smoke_test())  # noqa: T201 - CLI entrypoint
