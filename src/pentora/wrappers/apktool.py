"""apktool -- Android APK decompiler wrapper."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pentora.wrappers.base import ToolWrapper


@dataclass
class ApkDecompileResult:
    output_dir: Path
    manifest_found: bool
    source_dirs: list[str]


class ApktoolWrapper(ToolWrapper):
    tool_name = "apktool"
    install_check_argv = ["apktool", "--version"]

    def build_argv(self, apk_path: str, output_dir: str) -> list[str]:
        return [self.tool_name, "d", "-f", "-o", output_dir, apk_path]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[ApkDecompileResult]:
        """Return decompile result if successful (returncode 0)."""
        if returncode != 0:
            return []
        lines = stdout.splitlines()
        manifest = any("AndroidManifest.xml" in line for line in lines)
        smali_dirs = [line.strip() for line in lines if "smali" in line.lower()]
        return [
            ApkDecompileResult(
                output_dir=Path("."),
                manifest_found=manifest,
                source_dirs=smali_dirs,
            )
        ]
