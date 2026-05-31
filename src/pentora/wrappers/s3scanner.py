"""s3scanner -- open S3 bucket scanner wrapper."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from pentora.wrappers.base import ToolWrapper


@dataclass
class S3BucketFinding:
    bucket: str
    public_read: bool
    public_write: bool
    region: str


class S3ScannerWrapper(ToolWrapper):
    tool_name = "s3scanner"
    install_check_argv = ["s3scanner", "--help"]

    def build_argv(self, bucket_file: str) -> list[str]:
        return [self.tool_name, "scan", "--json", "--file", bucket_file]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[S3BucketFinding]:
        """Parse s3scanner JSON array output, return open bucket findings."""
        text = stdout.strip()
        if not text:
            return []
        try:
            data: list[dict[str, Any]] = json.loads(text)
        except json.JSONDecodeError:
            return []

        findings: list[S3BucketFinding] = []
        for item in data:
            if item.get("exists") and (item.get("public_read") or item.get("public_write")):
                findings.append(
                    S3BucketFinding(
                        bucket=str(item.get("bucket", "")),
                        public_read=bool(item.get("public_read")),
                        public_write=bool(item.get("public_write")),
                        region=str(item.get("region", "")),
                    )
                )
        return findings
