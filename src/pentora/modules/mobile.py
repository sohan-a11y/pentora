"""Mobile phase -- APK static analysis via apktool/jadx/MobSF (graceful degradation)."""
from __future__ import annotations

import logging
import re

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.security.secret_patterns import SECRET_PATTERNS
from pentora.wrappers.apktool import ApktoolWrapper
from pentora.wrappers.base import ToolNotInstalled
from pentora.wrappers.jadx import JadxWrapper

log = logging.getLogger(__name__)

_APK_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # noqa: S105

# Pre-compile secret patterns for file scanning
_COMPILED_PATTERNS = [
    (entry["name"], re.compile(entry["pattern"]))
    for entry in SECRET_PATTERNS
]


class MobileModule(PhaseModule):
    name = "mobile"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        # Only runs if apk_path is set (via ctx attribute or ctx.extra)
        apk_path = (
            getattr(ctx, "apk_path", None)
            or (ctx.config.profiles.get("generic", {}).get("apk_path"))
        )
        if not apk_path:
            log.debug("mobile: no apk_path set, skipping")
            return []

        findings: list[Finding] = []

        # Step 1: decompile with apktool
        try:
            apktool = ApktoolWrapper(log_dir=ctx.output_dir / "logs" / "tool-invocations")
            out_dir = ctx.output_dir / "mobile_decompiled"
            results = await apktool.run(str(apk_path), str(out_dir))
        except ToolNotInstalled:
            log.warning("mobile: apktool not installed, skipping")
            return []
        except Exception as e:  # noqa: BLE001
            log.warning("mobile: apktool failed: %s", e)
            return []

        # Step 2: scan decompiled output for secrets
        for decompile_result in results:
            findings += _scan_dir_for_secrets(
                str(decompile_result.output_dir), str(apk_path)
            )

        # Step 3: try jadx as well (best-effort)
        try:
            jadx = JadxWrapper(log_dir=ctx.output_dir / "logs" / "tool-invocations")
            jadx_out = ctx.output_dir / "mobile_jadx"
            jadx_results = await jadx.run(str(apk_path), str(jadx_out))
            for jr in jadx_results:
                findings += _scan_dir_for_secrets(str(jr.output_dir), str(apk_path))
        except (ToolNotInstalled, Exception):  # noqa: BLE001
            log.debug("mobile: jadx not installed or failed, skipping jadx step")

        for f in findings:
            if ctx.store:
                await ctx.store.add(f)
        return findings


def _scan_dir_for_secrets(directory: str, apk_path: str) -> list[Finding]:
    """Recursively scan all files in directory for secret patterns."""
    import os
    findings: list[Finding] = []
    for root, _dirs, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8", errors="replace") as fh:  # noqa: ASYNC230
                    content = fh.read()
            except OSError:
                continue
            for name, compiled in _COMPILED_PATTERNS:
                if compiled.search(content):
                    findings.append(
                        Finding(
                            module="mobile.secret",
                            title=f"Secret Disclosure in APK: {name}",
                            endpoint=apk_path,
                            method="STATIC",
                            evidence=f"Pattern '{name}' found in {fpath}",
                            cvss=CVSS.from_vector(_APK_VECTOR),
                            description=(
                                f"The decompiled APK contains a potential {name} "
                                "credential in source."
                            ),
                            remediation=(
                                "Remove hardcoded credentials from source code. "
                                "Use Android Keystore or environment configuration."
                            ),
                        )
                    )
    return findings
