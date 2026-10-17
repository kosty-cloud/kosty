"""Offline tests for cli/utils._run_checks error surfacing.

No boto3/STS/network: the session is a MagicMock the stub checks never touch,
and the checks run in the real ThreadPoolExecutor but only return lists or
raise in-process.
"""

from unittest.mock import MagicMock

from kosty.cli.utils import _run_checks
from kosty.core.models import CheckMetadata, Finding, Severity, FindingType


def _check_entry(check_id: str, func, compliance_ids=None):
    """Build a registry-style check dict with real CheckMetadata."""
    return {
        'metadata': CheckMetadata(
            check_id=check_id,
            service="EC2",
            provider="aws",
            finding_type=FindingType.COST,
            compliance_ids=compliance_ids or {},
        ),
        'func': func,
    }


def _finding():
    return Finding(
        check_id="aws-ec2-001",
        service="EC2",
        resource_id="i-abc",
        region="us-east-1",
        account_id="123456789012",
        issue="Idle",
        severity=Severity.LOW,
        finding_type=FindingType.COST,
    )


def test_run_checks_collects_findings():
    """A passing check contributes its findings and no errors."""
    def ok(session, region, **kwargs):
        return [_finding()]

    findings, errors = _run_checks(
        [_check_entry("aws-ec2-001", ok)],
        MagicMock(), ["us-east-1"], 2, None,
    )
    assert len(findings) == 1
    assert errors == []


def test_run_checks_surfaces_raising_check():
    """A raising check is recorded in errors instead of being swallowed."""
    def boom(session, region, **kwargs):
        raise RuntimeError("permission problem")

    findings, errors = _run_checks(
        [_check_entry("aws-ec2-002", boom)],
        MagicMock(), ["us-east-1"], 2, None,
    )
    assert findings == []
    assert len(errors) == 1
    check_id, region, exc_type, message = errors[0]
    assert check_id == "aws-ec2-002"
    assert region == "us-east-1"
    assert exc_type == "RuntimeError"
    assert "permission problem" in message


def test_run_checks_mixed_pass_and_fail():
    """Passing and failing checks are separated across findings and errors."""
    def ok(session, region, **kwargs):
        return [_finding()]

    def boom(session, region, **kwargs):
        raise ValueError("bad")

    findings, errors = _run_checks(
        [_check_entry("ok-1", ok), _check_entry("fail-1", boom)],
        MagicMock(), ["us-east-1"], 4, None,
    )
    assert len(findings) == 1
    assert len(errors) == 1
    assert errors[0][0] == "fail-1"


def test_run_checks_injects_compliance_ids():
    """compliance_ids from metadata are injected into findings that lack them."""
    def ok(session, region, **kwargs):
        return [_finding()]

    findings, errors = _run_checks(
        [_check_entry("ok-1", ok, compliance_ids={"CIS": ["1.1"]})],
        MagicMock(), ["us-east-1"], 2, None,
    )
    assert findings[0].compliance_ids == {"CIS": ["1.1"]}
    assert errors == []
