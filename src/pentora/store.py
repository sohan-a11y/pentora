"""SQLite-backed async findings store."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import aiosqlite

from pentora.finding import CVSS, Finding, Severity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    module TEXT NOT NULL,
    title TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    evidence TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    cvss_vector TEXT NOT NULL,
    cvss_score REAL NOT NULL,
    severity TEXT NOT NULL,
    request_raw TEXT NOT NULL DEFAULT '',
    response_raw TEXT NOT NULL DEFAULT '',
    screenshot_path TEXT,
    discovered_at TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'pentora',
    extra TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_module ON findings(module);
"""

_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FindingsStore:
    def __init__(self, db_path: Path):
        self._path = db_path

    async def init(self) -> None:
        async with aiosqlite.connect(self._path) as db:
            await db.executescript(_SCHEMA)
            await db.commit()

    async def add(self, f: Finding) -> None:
        async with aiosqlite.connect(self._path) as db:
            await db.execute(
                """
                INSERT OR IGNORE INTO findings
                (id, module, title, endpoint, method, evidence, description, remediation,
                 cvss_vector, cvss_score, severity, request_raw, response_raw,
                 screenshot_path, discovered_at, source, extra)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f.id, f.module, f.title, f.endpoint, f.method, f.evidence,
                    f.description, f.remediation,
                    f.cvss.vector, f.cvss.score, f.severity.value,
                    f.request_raw, f.response_raw, f.screenshot_path,
                    f.discovered_at.isoformat(), f.source, json.dumps(f.extra),
                ),
            )
            await db.commit()

    async def count(self) -> int:
        async with aiosqlite.connect(self._path) as db:
            cur = await db.execute("SELECT COUNT(*) FROM findings")
            row = await cur.fetchone()
        return int(row[0]) if row else 0

    async def all(self) -> list[Finding]:
        async with aiosqlite.connect(self._path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM findings ORDER BY cvss_score DESC")
            rows = await cur.fetchall()
        return [self._row_to_finding(r) for r in rows]

    async def by_min_severity(self, min_severity: str) -> list[Finding]:
        threshold = _SEVERITY_ORDER[Severity[min_severity.upper()]]
        results = []
        for f in await self.all():
            if _SEVERITY_ORDER[f.severity] >= threshold:
                results.append(f)
        return results

    @staticmethod
    def _row_to_finding(row: aiosqlite.Row) -> Finding:
        return Finding(
            module=row["module"],
            title=row["title"],
            endpoint=row["endpoint"],
            method=row["method"],
            evidence=row["evidence"],
            description=row["description"],
            remediation=row["remediation"],
            cvss=CVSS(vector=row["cvss_vector"], score=row["cvss_score"]),
            request_raw=row["request_raw"],
            response_raw=row["response_raw"],
            screenshot_path=row["screenshot_path"],
            discovered_at=datetime.fromisoformat(row["discovered_at"]),
            source=row["source"],
            extra=json.loads(row["extra"]),
        )
