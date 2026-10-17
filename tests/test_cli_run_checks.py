"""Offline tests for the unified service-command output path (cli/utils).

Since 3.4.0 the per-service commands run through ScanEngine.run_service and
persist through StorageManager, so --save-to accepts both local paths and
s3:// URLs. These tests exercise the output boundary (_output_findings) only;
engine execution is covered in test_engine_run_service.py.

No boto3/STS/network: boto3 is stubbed in sys.modules before importing the
storage layer (storage.py imports boto3 at module top), and StorageManager is
patched at its save_file boundary so no real S3 call is ever made.
"""

import sys
import types
from unittest.mock import AsyncMock, patch

import pytest

# Stub boto3 so importing kosty.core.storage (imported lazily by cli.utils)
# never pulls the real SDK or triggers network/credential lookups.
if 'boto3' not in sys.modules:
    sys.modules['boto3'] = types.ModuleType('boto3')

from kosty.cli.utils import _output_findings, _serialize_findings_json, _serialize_findings_csv
from kosty.core.models import Finding, Severity, FindingType


def _finding():
    return Finding(
        check_id="aws-ec2-001",
        service="EC2",
        resource_id="i-abc",
        region="us-east-1",
        account_id="123456789012",
        issue="Idle instance",
        severity=Severity.LOW,
        finding_type=FindingType.COST,
    )


# ---------------------------------------------------------------------------
# (3) --save-to s3:// is recognized on the service path
# ---------------------------------------------------------------------------

def test_output_findings_routes_s3_save_to():
    """A s3:// --save-to reaches StorageManager.save_file with the s3 string."""
    saved = AsyncMock(return_value="s3://bucket/path/report.json")
    with patch("kosty.core.storage.StorageManager.save_file", saved):
        _output_findings([_finding()], "EC2", "json",
                         save_to="s3://bucket/path/")

    assert saved.await_count == 1
    args, kwargs = saved.call_args
    # save_file(content, filename, save_to, file_format, allow_outside_cwd=...)
    assert args[2] == "s3://bucket/path/"
    assert args[3] == "json"


def test_output_findings_local_save_to_passes_through():
    """A local --save-to is forwarded verbatim; confinement lives in storage."""
    saved = AsyncMock(return_value="/cwd/report.json")
    with patch("kosty.core.storage.StorageManager.save_file", saved):
        _output_findings([_finding()], "EC2", "csv",
                         save_to="reports/", allow_outside_cwd=True)

    assert saved.await_count == 1
    args, kwargs = saved.call_args
    assert args[2] == "reports/"
    assert args[3] == "csv"
    assert kwargs.get("allow_outside_cwd") is True


def test_output_findings_console_does_not_write(capsys):
    """Console output writes nothing to storage and prints the service header."""
    saved = AsyncMock()
    with patch("kosty.core.storage.StorageManager.save_file", saved):
        _output_findings([_finding()], "EC2", "console")

    assert saved.await_count == 0
    out = capsys.readouterr().out
    assert "EC2: 1 issues found" in out


# ---------------------------------------------------------------------------
# serialization helpers keep the preserved service report shape
# ---------------------------------------------------------------------------

def test_serialize_findings_json_shape():
    """JSON report keeps {scan_timestamp, service, total_issues, results}."""
    import json
    items = [_finding().to_dict()]
    content = _serialize_findings_json(items, "EC2", len(items))
    data = json.loads(content)
    assert set(data.keys()) == {"scan_timestamp", "service", "total_issues", "results"}
    assert data["service"] == "EC2"
    assert data["total_issues"] == 1
    assert data["results"][0]["ResourceId"] == "i-abc"


def test_serialize_findings_csv_empty_is_blank():
    """An empty finding set serializes to an empty CSV string."""
    assert _serialize_findings_csv([]) == ""


def test_serialize_findings_csv_has_header_and_row():
    """A non-empty set yields a header line plus one data row."""
    items = [_finding().to_dict()]
    content = _serialize_findings_csv(items)
    lines = [l for l in content.splitlines() if l.strip()]
    assert len(lines) == 2
    assert "Issue" in lines[0]
