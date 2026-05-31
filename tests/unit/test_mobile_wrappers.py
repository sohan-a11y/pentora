"""Tests for apktool, jadx, and MobSF wrappers."""
from __future__ import annotations

import json
from pathlib import Path

from pentora.wrappers.apktool import ApkDecompileResult, ApktoolWrapper
from pentora.wrappers.jadx import JadxDecompileResult, JadxWrapper
from pentora.wrappers.mobsf import MobsfIssue, MobsfWrapper

# --- apktool ---

def test_apktool_parse_success() -> None:
    wrapper = ApktoolWrapper()
    result = wrapper.parse(
        stdout="Decoding AndroidManifest.xml\nsmali/com/example\n",
        stderr="",
        returncode=0,
    )
    assert len(result) == 1
    assert isinstance(result[0], ApkDecompileResult)
    assert result[0].manifest_found is True


def test_apktool_parse_failure() -> None:
    wrapper = ApktoolWrapper()
    result = wrapper.parse(stdout="", stderr="error", returncode=1)
    assert result == []


def test_apktool_build_argv() -> None:
    wrapper = ApktoolWrapper()
    argv = wrapper.build_argv("/tmp/app.apk", "/tmp/out")
    assert "apktool" in argv
    assert "/tmp/app.apk" in argv
    assert "-f" in argv


# --- jadx ---

def test_jadx_parse_success() -> None:
    wrapper = JadxWrapper()
    stdout = "Decompile: Main.java\nDecompile: Helper.java\nDecompile: Utils.java\n"
    result = wrapper.parse(stdout=stdout, stderr="", returncode=0)
    assert len(result) == 1
    assert isinstance(result[0], JadxDecompileResult)
    assert result[0].class_count == 3


def test_jadx_parse_failure() -> None:
    wrapper = JadxWrapper()
    assert wrapper.parse(stdout="", stderr="", returncode=1) == []


def test_jadx_build_argv() -> None:
    wrapper = JadxWrapper()
    argv = wrapper.build_argv("/tmp/app.apk", "/tmp/out")
    assert "jadx" in argv
    assert "-d" in argv


# --- MobSF ---

def test_mobsf_parse_report_json() -> None:
    fixture = Path("tests/fixtures/mobsf/scan_report.json").read_text()
    data = json.loads(fixture)
    wrapper = MobsfWrapper()
    issues = wrapper.parse_report_json(data)
    assert len(issues) >= 1
    assert all(isinstance(i, MobsfIssue) for i in issues)
    high = [i for i in issues if i.severity == "HIGH"]
    assert len(high) >= 1
    assert "Hardcoded" in high[0].title or "Credentials" in high[0].title


def test_mobsf_parse_empty_report() -> None:
    wrapper = MobsfWrapper()
    issues = wrapper.parse_report_json({})
    assert issues == []
