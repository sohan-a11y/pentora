"""Tests for s3scanner and awsbucketdump wrappers."""
from __future__ import annotations

from pathlib import Path

from pentora.wrappers.awsbucketdump import AwsBucketDumpWrapper, BucketDumpResult
from pentora.wrappers.s3scanner import S3BucketFinding, S3ScannerWrapper

# --- s3scanner ---

def test_s3scanner_parses_vulnerable_json() -> None:
    fixture = Path("tests/fixtures/s3scanner/vulnerable.json").read_text()
    wrapper = S3ScannerWrapper()
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) == 2
    assert all(isinstance(r, S3BucketFinding) for r in results)
    buckets = [r.bucket for r in results]
    assert "pure-app" in buckets


def test_s3scanner_clean_no_findings() -> None:
    fixture = Path("tests/fixtures/s3scanner/clean.json").read_text()
    wrapper = S3ScannerWrapper()
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert results == []


def test_s3scanner_empty_output() -> None:
    wrapper = S3ScannerWrapper()
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []


def test_s3scanner_build_argv() -> None:
    wrapper = S3ScannerWrapper()
    argv = wrapper.build_argv("/tmp/buckets.txt")
    assert "s3scanner" in argv
    assert "--json" in argv


# --- awsbucketdump ---

def test_awsbucketdump_parses_output() -> None:
    fixture = Path("tests/fixtures/awsbucketdump/output.txt").read_text()
    wrapper = AwsBucketDumpWrapper()
    results = wrapper.parse(stdout=fixture, stderr="", returncode=0)
    assert len(results) >= 1
    assert isinstance(results[0], BucketDumpResult)
    assert "pure-data" in results[0].bucket


def test_awsbucketdump_empty_output() -> None:
    wrapper = AwsBucketDumpWrapper()
    assert wrapper.parse(stdout="", stderr="", returncode=0) == []


def test_awsbucketdump_build_argv() -> None:
    wrapper = AwsBucketDumpWrapper()
    argv = wrapper.build_argv("pure-app", "/tmp/out")
    assert "AWSBucketDump" in argv
    assert "pure-app" in argv
