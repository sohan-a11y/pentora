"""Output-format reporters — registry of all 11 built-in reporters."""
from __future__ import annotations

from pentora.reporters.base import Reporter
from pentora.reporters.burp_xml import BurpXmlReporter
from pentora.reporters.csv_reporter import CsvReporter
from pentora.reporters.defectdojo import DefectDojoReporter
from pentora.reporters.faraday import FaradayReporter
from pentora.reporters.finding_folder import FindingFolderReporter
from pentora.reporters.har import HarReporter
from pentora.reporters.html import HtmlReporter
from pentora.reporters.json_reporter import JsonReporter
from pentora.reporters.markdown import MarkdownReporter
from pentora.reporters.sarif import SarifReporter
from pentora.reporters.zap_xml import ZapXmlReporter

ALL_REPORTERS: list[Reporter] = [
    JsonReporter(),
    MarkdownReporter(),
    HtmlReporter(),
    FindingFolderReporter(),
    SarifReporter(),
    CsvReporter(),
    DefectDojoReporter(),
    FaradayReporter(),
    BurpXmlReporter(),
    ZapXmlReporter(),
    HarReporter(),
]

REPORTER_MAP: dict[str, Reporter] = {r.name: r for r in ALL_REPORTERS}

__all__ = ["ALL_REPORTERS", "REPORTER_MAP", "Reporter"]
