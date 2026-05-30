"""dalfox — fast parameter-based XSS scanner (parses --format json)."""
from __future__ import annotations

import json
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper


@dataclass
class DalfoxHit:
    param: str
    payload: str
    type: str
    severity: str


class DalfoxWrapper(ToolWrapper):
    tool_name = "dalfox"
    install_check_argv = ["dalfox", "version"]

    def build_argv(self, url: str) -> list[str]:
        return [self.tool_name, "url", url, "--silence", "--format", "json"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[DalfoxHit]:
        if not stdout.strip():
            return []
        records = self._load_records(stdout)
        out: list[DalfoxHit] = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            out.append(
                DalfoxHit(
                    param=str(rec.get("param", "")),
                    payload=str(rec.get("payload", "")),
                    type=str(rec.get("type", "")),
                    severity=str(rec.get("severity", "")),
                )
            )
        return out

    @staticmethod
    def _load_records(stdout: str) -> list[object]:
        """Dalfox emits either a JSON array or one JSON object per line."""
        text = stdout.strip()
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            records: list[object] = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return records
        if isinstance(doc, list):
            return doc
        return [doc]
