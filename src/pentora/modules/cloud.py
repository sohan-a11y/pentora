"""Cloud phase -- probe Firebase, S3, Azure, GCS for open/misconfigured buckets."""
from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from pentora.context import ScanContext
from pentora.finding import CVSS, Finding
from pentora.modules.base import PhaseModule
from pentora.wrappers.s3scanner import S3ScannerWrapper

log = logging.getLogger(__name__)

_FIREBASE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"  # noqa: S105
_BUCKET_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # noqa: S105
_AZURE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # noqa: S105


def _derive_names(target: str) -> list[str]:
    """Derive cloud name candidates from target URL."""
    host = urlparse(target).hostname or target
    # e.g. pure.app -> ["pure", "pureapp", "pure-app"]
    parts = host.split(".")
    base = parts[0] if parts else host
    second = parts[1] if len(parts) > 1 else ""
    candidates = [base]
    if second and second not in ("com", "app", "io", "net", "org"):
        candidates.append(base + second)
        candidates.append(f"{base}-{second}")
    return list(dict.fromkeys(candidates))  # deduplicate, preserve order


class CloudModule(PhaseModule):
    name = "cloud"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        names = _derive_names(ctx.target)
        findings: list[Finding] = []

        async with httpx.AsyncClient(
            follow_redirects=True, timeout=10.0, verify=False  # noqa: S501
        ) as client:
            for name in names:
                findings += await _probe_firebase(client, name, ctx.target)
                findings += await _probe_azure(client, name, ctx.target)
                findings += await _probe_gcs(client, name, ctx.target)

        # S3 via s3scanner (mocked in tests)
        try:
            wrapper = S3ScannerWrapper()
            # We don't write a temp file in the scan; pass names as CSV
            import tempfile
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tf:
                tf.write("\n".join(names) + "\n")
                tf_path = tf.name
            s3_results = await wrapper.run(tf_path)
            for result in s3_results:
                access = "read+write" if result.public_write else "read"
                vec = _FIREBASE_VECTOR if result.public_write else _BUCKET_VECTOR
                findings.append(
                    Finding(
                        module="cloud.s3",
                        title=f"Open S3 Bucket: {result.bucket}",
                        endpoint=f"https://{result.bucket}.s3.amazonaws.com/",
                        method="GET",
                        evidence=f"Public {access} access on bucket {result.bucket!r}",
                        cvss=CVSS.from_vector(vec),
                        description=f"S3 bucket {result.bucket!r} is publicly accessible.",
                        remediation="Apply a bucket policy to restrict public access.",
                    )
                )
        except Exception:  # noqa: BLE001,S110 - tool may not be installed
            pass

        for f in findings:
            if ctx.store:
                await ctx.store.add(f)
        return findings


async def _probe_firebase(
    client: httpx.AsyncClient, name: str, target: str
) -> list[Finding]:
    url = f"https://{name}.firebaseio.com/.json"
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return []
    if resp.status_code == 200:
        body = resp.text.strip()
        if body and body != "null":
            return [
                Finding(
                    module="cloud.firebase",
                    title=f"Open Firebase Database: {name}",
                    endpoint=url,
                    method="GET",
                    evidence=f"GET {url} => 200, data returned",
                    cvss=CVSS.from_vector(_FIREBASE_VECTOR),
                    description=(
                        f"Firebase Realtime Database {name!r} is publicly readable."
                    ),
                    remediation="Apply Firebase security rules to restrict public access.",
                )
            ]
    return []


async def _probe_azure(
    client: httpx.AsyncClient, name: str, target: str
) -> list[Finding]:
    url = f"https://{name}.blob.core.windows.net/$web/index.html"
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return []
    if resp.status_code == 200:
        return [
            Finding(
                module="cloud.azure",
                title=f"Open Azure Blob Container: {name}",
                endpoint=url,
                method="GET",
                evidence=f"GET {url} => 200",
                cvss=CVSS.from_vector(_AZURE_VECTOR),
                description=f"Azure Blob container {name!r} is publicly readable.",
                remediation="Set container access level to 'Private'.",
            )
        ]
    return []


async def _probe_gcs(
    client: httpx.AsyncClient, name: str, target: str
) -> list[Finding]:
    url = f"https://storage.googleapis.com/{name}/"
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return []
    if resp.status_code == 200:
        return [
            Finding(
                module="cloud.gcs",
                title=f"Open GCS Bucket: {name}",
                endpoint=url,
                method="GET",
                evidence=f"GET {url} => 200",
                cvss=CVSS.from_vector(_AZURE_VECTOR),
                description=f"GCS bucket {name!r} is publicly listable.",
                remediation="Set bucket IAM to restrict public access.",
            )
        ]
    return []
