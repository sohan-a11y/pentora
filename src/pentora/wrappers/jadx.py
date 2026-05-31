"""jadx -- Java decompiler wrapper for Android APK analysis."""
from __future__ import annotations

from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper


@dataclass
class JadxDecompileResult:
    output_dir: str
    class_count: int


class JadxWrapper(ToolWrapper):
    tool_name = "jadx"
    install_check_argv = ["jadx", "--version"]

    def build_argv(self, apk_path: str, output_dir: str) -> list[str]:
        return [self.tool_name, "-d", output_dir, apk_path]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[JadxDecompileResult]:
        """Parse jadx output to get decompile info."""
        if returncode != 0:
            return []
        # Count mentions of .java files in output
        class_count = stdout.count(".java")
        return [JadxDecompileResult(output_dir=".", class_count=class_count)]
