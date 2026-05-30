from datetime import UTC, datetime

from pentora.finding import CVSS, Finding, Severity


def test_severity_from_cvss_score() -> None:
    assert Severity.from_score(9.5) is Severity.CRITICAL
    assert Severity.from_score(7.0) is Severity.HIGH
    assert Severity.from_score(4.0) is Severity.MEDIUM
    assert Severity.from_score(0.5) is Severity.LOW
    assert Severity.from_score(0.0) is Severity.INFO


def test_cvss_vector_round_trip() -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cvss = CVSS.from_vector(vector)
    assert cvss.vector == vector
    assert cvss.score == 9.8  # known canonical score
    assert cvss.severity is Severity.CRITICAL


def test_finding_id_is_deterministic_for_same_inputs() -> None:
    a = Finding(
        module="authz.idor",
        title="IDOR on /api/users/{id}",
        endpoint="https://x.com/api/users/12345",
        method="GET",
        evidence="Returned User B's email",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    )
    b = Finding(
        module="authz.idor",
        title="IDOR on /api/users/{id}",
        endpoint="https://x.com/api/users/12345",
        method="GET",
        evidence="Returned User B's email",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    )
    assert a.id == b.id  # deterministic SHA256 of canonical fields


def test_finding_has_timestamp() -> None:
    f = Finding(
        module="recon",
        title="Subdomain found",
        endpoint="https://api.x.com",
        method="-",
        evidence="From subfinder",
        cvss=CVSS.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    )
    assert f.discovered_at <= datetime.now(UTC)
