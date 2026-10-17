"""Offline tests for kosty.core.reporter.

No boto3/STS/network: Findings are built by hand, reports are written under
tmp_path (chdir), and no save_to/S3 path is exercised.
"""

import json
import os

from kosty.core.reporter import (
    CostOptimizationReporter,
    sanitize_csv_field,
    _write_with_hash,
)
from kosty.core.models import Finding, Severity, FindingType


def _finding(resource_id="i-abc", issue="Idle instance", savings=12.5,
             finding_type=FindingType.COST, severity=Severity.MEDIUM):
    return Finding(
        check_id="aws-ec2-001",
        service="EC2",
        resource_id=resource_id,
        region="us-east-1",
        account_id="123456789012",
        issue=issue,
        severity=severity,
        finding_type=finding_type,
        monthly_savings=savings,
    )


# ---------------------------------------------------------------------------
# CSV injection neutralization
# ---------------------------------------------------------------------------

def test_sanitize_csv_field_prefixes_formula_characters():
    """A value starting with = + - @ gets a leading apostrophe."""
    for ch in ('=', '+', '-', '@'):
        assert sanitize_csv_field(f"{ch}cmd()") == f"'{ch}cmd()"


def test_sanitize_csv_field_leaves_plain_text():
    """Ordinary text is returned unchanged."""
    assert sanitize_csv_field("i-0123abc") == "i-0123abc"


def test_sanitize_csv_field_stringifies_non_str():
    """Non-string values are stringified and untouched."""
    assert sanitize_csv_field(42) == "42"
    assert sanitize_csv_field(None) == "None"


# ---------------------------------------------------------------------------
# add_results + save_json_report
# ---------------------------------------------------------------------------

def test_add_results_aggregates_savings():
    """add_results stores items and sums monthly_savings for the group."""
    reporter = CostOptimizationReporter()
    data = [_finding(savings=10.0).to_dict(), _finding(savings=5.0).to_dict()]
    reporter.add_results("ec2", "idle", data, account_id="123456789012")
    group = reporter.results["123456789012"]["ec2"]["idle"]
    assert group['count'] == 2
    assert group['monthly_savings'] == 15.0


def test_save_json_report_writes_valid_json_and_sidecar(tmp_path, monkeypatch):
    """save_json_report writes a valid JSON file plus a .sha256 sidecar."""
    monkeypatch.chdir(tmp_path)
    reporter = CostOptimizationReporter()
    reporter.add_results("ec2", "idle", [_finding().to_dict()], account_id="123456789012")

    filename = reporter.save_json_report(filename="report.json")
    assert os.path.exists(filename)

    with open(filename) as fh:
        payload = json.load(fh)
    assert payload['total_issues'] == 1
    assert "123456789012" in payload['results']

    assert os.path.exists(filename + ".sha256")


def test_sidecar_records_basename_only(tmp_path):
    """_write_with_hash records the basename, not the full path, in the sidecar."""
    target = tmp_path / "sub"
    target.mkdir()
    report_path = str(target / "report.json")
    _write_with_hash("content", report_path)

    sidecar = report_path + ".sha256"
    line = open(sidecar).read().strip()
    digest, name = line.split("  ", 1)
    assert name == "report.json"
    assert "/" not in name


# ---------------------------------------------------------------------------
# save_csv_report with a formula-injection value
# ---------------------------------------------------------------------------

def test_save_csv_report_neutralizes_injection(tmp_path, monkeypatch):
    """A resource id starting with '=' is neutralized in the CSV output."""
    monkeypatch.chdir(tmp_path)
    reporter = CostOptimizationReporter()
    data = [_finding(resource_id="=HYPERLINK(1)").to_dict()]
    reporter.add_results("ec2", "idle", data, account_id="123456789012")

    filename = reporter.save_csv_report(filename="report.csv")
    text = open(filename).read()
    assert "'=HYPERLINK(1)" in text
    assert "\n=HYPERLINK(1)" not in text
