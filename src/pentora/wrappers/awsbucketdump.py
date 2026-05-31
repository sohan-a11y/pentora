"""AWSBucketDump -- AWS S3 bucket content enumerator wrapper."""
from __future__ import annotations

import re
from dataclasses import dataclass

from pentora.wrappers.base import ToolWrapper

_BUCKET_RE = re.compile(r"Found public bucket:\s*(.+)", re.I)


@dataclass
class BucketDumpResult:
    bucket: str
    read_public: bool


class AwsBucketDumpWrapper(ToolWrapper):
    tool_name = "AWSBucketDump"
    install_check_argv = ["AWSBucketDump", "--help"]

    def build_argv(self, bucket: str, output_dir: str) -> list[str]:
        return [self.tool_name, "-D", "-l", bucket, "-g", "interesting_Keywords.txt"]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[BucketDumpResult]:
        """Parse AWSBucketDump text output."""
        results: list[BucketDumpResult] = []
        for line in stdout.splitlines():
            m = _BUCKET_RE.search(line)
            if m:
                results.append(
                    BucketDumpResult(
                        bucket=m.group(1).strip(),
                        read_public=True,
                    )
                )
        return results
