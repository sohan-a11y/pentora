"""Per-finding folder bundle reporter.

One folder per finding with request/response/PoC/screenshot.
"""
from __future__ import annotations

import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from pentora.finding import Finding
from pentora.reporters.base import Reporter

_SAFE = re.compile(r"[^a-z0-9]+")


def _slug(s: str) -> str:
    return _SAFE.sub("_", s.lower()).strip("_")[:50]


class FindingFolderReporter(Reporter):
    name = "finding_folder"
    output_filename = "findings/"

    def __init__(self) -> None:
        tpl_dir = Path(__file__).parent.parent / "templates"
        self._env = Environment(
            loader=FileSystemLoader(str(tpl_dir)),
            autoescape=select_autoescape(disabled_extensions=("sh", "py", "j2")),
        )

    async def write(self, output_dir: Path, findings: list[Finding], target: str) -> Path:
        root = output_dir / "findings"
        root.mkdir(exist_ok=True)
        for f in findings:
            ts = f.discovered_at.strftime("%Y%m%d_%H%M%S")
            folder = root / f"{ts}_{_slug(f.module)}_{_slug(f.title)}"
            folder.mkdir(exist_ok=True)
            (folder / "finding.md").write_text(
                self._env.get_template("finding.md.j2").render(f=f), encoding="utf-8"
            )
            (folder / "poc.sh").write_text(
                self._env.get_template("poc.sh.j2").render(f=f), encoding="utf-8"
            )
            (folder / "poc.sh").chmod(0o755)
            (folder / "request.http").write_text(f.request_raw or "", encoding="utf-8")
            (folder / "response.http").write_text(f.response_raw or "", encoding="utf-8")
        return root
