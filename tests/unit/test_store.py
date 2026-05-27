import pytest
from pathlib import Path

from pentora.finding import CVSS, Finding
from pentora.store import FindingsStore


@pytest.mark.asyncio
async def test_store_persists_and_retrieves_finding(tmp_path: Path) -> None:
    db = tmp_path / "findings.db"
    store = FindingsStore(db)
    await store.init()

    f = Finding(
        module="recon",
        title="Subdomain found",
        endpoint="https://api.x.com",
        method="-",
        evidence="From subfinder",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    )
    await store.add(f)
    rows = await store.all()
    assert len(rows) == 1
    assert rows[0].id == f.id


@pytest.mark.asyncio
async def test_store_deduplicates_on_id(tmp_path: Path) -> None:
    db = tmp_path / "findings.db"
    store = FindingsStore(db)
    await store.init()

    f = Finding(
        module="recon",
        title="dup",
        endpoint="https://x.com",
        method="-",
        evidence="e",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    )
    await store.add(f)
    await store.add(f)  # same ID — no duplicate
    assert len(await store.all()) == 1


@pytest.mark.asyncio
async def test_store_filter_by_severity(tmp_path: Path) -> None:
    db = tmp_path / "findings.db"
    store = FindingsStore(db)
    await store.init()

    high = Finding(
        module="injection",
        title="SQLi",
        endpoint="https://x.com/search",
        method="GET",
        evidence="time-based",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    )
    low = Finding(
        module="headers",
        title="Missing HSTS",
        endpoint="https://x.com/",
        method="GET",
        evidence="No Strict-Transport-Security header",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    )
    await store.add(high)
    await store.add(low)

    criticals_and_highs = await store.by_min_severity("HIGH")
    assert len(criticals_and_highs) == 1
    assert criticals_and_highs[0].title == "SQLi"
