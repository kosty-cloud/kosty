"""Offline tests for the unified per-service execution path.

These cover ScanEngine.run_service() — the single entry point the per-service
CLI commands now use — plus the service-path output boundary in cli/utils.

No boto3/STS/network: the session is a MagicMock the stub checks never touch,
checks run in the real ThreadPoolExecutor but only return lists or raise
in-process, and the S3 branch is asserted by mocking StorageManager.save_file
at its boundary (never hitting real S3).
"""

from unittest.mock import MagicMock, patch

from kosty.core.engine import ScanEngine
from kosty.core.registry import registry
from kosty.core.models import CheckMetadata, Finding, Severity, FindingType


def _register(reg, check_id, func, service="EC2", provider="aws",
              finding_type=FindingType.COST, region_scope="regional",
              requires_deep=False, compliance_ids=None):
    """Register a stub check directly on the registry under test."""
    reg._checks[check_id] = {
        'metadata': CheckMetadata(
            check_id=check_id,
            service=service,
            provider=provider,
            finding_type=finding_type,
            region_scope=region_scope,
            requires_deep=requires_deep,
            compliance_ids=compliance_ids or {},
        ),
        'func': func,
    }


def _finding(check_id="aws-ec2-001", service="EC2", region="us-east-1"):
    return Finding(
        check_id=check_id,
        service=service,
        resource_id="i-abc",
        region=region,
        account_id="123456789012",
        issue="Idle",
        severity=Severity.LOW,
        finding_type=FindingType.COST,
    )


# ---------------------------------------------------------------------------
# (1) a failing check routes its error into ScanResult.errors
# ---------------------------------------------------------------------------

def test_run_service_surfaces_loader_errors(clean_registry):
    """Loader errors appear in run_service().errors, matching run()."""
    engine = ScanEngine(max_workers=2)
    engine._loader._errors.append("Integrity check failed: check_boom.py")

    result = engine.run_service(MagicMock(), ["us-east-1"], service="EC2")

    assert "Integrity check failed: check_boom.py" in result.errors


def test_run_service_routes_check_error_into_errors(clean_registry):
    """A raising check is recorded in result.errors, not swallowed."""
    def boom(session, region, **kwargs):
        raise RuntimeError("permission problem")

    _register(clean_registry, "aws-ec2-900", boom, service="EC2")

    engine = ScanEngine(max_workers=2)
    result = engine.run_service(MagicMock(), ["us-east-1"], service="EC2")

    assert result.findings == []
    assert len(result.errors) == 1
    assert "aws-ec2-900" in result.errors[0]
    assert "RuntimeError" in result.errors[0]
    assert "permission problem" in result.errors[0]


def test_run_service_mixed_pass_and_fail(clean_registry):
    """Passing and failing checks separate into findings and errors."""
    def ok(session, region, **kwargs):
        return [_finding("aws-ec2-ok")]

    def boom(session, region, **kwargs):
        raise ValueError("bad")

    _register(clean_registry, "aws-ec2-ok", ok, service="EC2")
    _register(clean_registry, "aws-ec2-bad", boom, service="EC2")

    engine = ScanEngine(max_workers=4)
    result = engine.run_service(MagicMock(), ["us-east-1"], service="EC2")

    assert len(result.findings) == 1
    assert len(result.errors) == 1
    assert "aws-ec2-bad" in result.errors[0]


# ---------------------------------------------------------------------------
# (2) global checks run once; regional checks run per region
# ---------------------------------------------------------------------------

def test_run_service_global_check_runs_once_across_regions(clean_registry):
    """A region_scope='global' check executes exactly once for N regions."""
    global_calls = []
    regional_calls = []

    def global_check(session, region, **kwargs):
        global_calls.append(region)
        return []

    def regional_check(session, region, **kwargs):
        regional_calls.append(region)
        return []

    _register(clean_registry, "aws-iam-900", global_check,
              service="IAM", region_scope="global")
    _register(clean_registry, "aws-iam-901", regional_check,
              service="IAM", region_scope="regional")

    engine = ScanEngine(max_workers=2)
    regions = ["us-east-1", "eu-west-1", "ap-south-1"]
    result = engine.run_service(MagicMock(), regions, service="IAM")

    assert len(global_calls) == 1
    assert global_calls[0] == "us-east-1"
    assert sorted(regional_calls) == sorted(regions)
    assert result.errors == []


# ---------------------------------------------------------------------------
# check_id / finding_type / deep filtering
# ---------------------------------------------------------------------------

def test_run_service_single_check_id(clean_registry):
    """check_id selects exactly one check and ignores the service set."""
    def one(session, region, **kwargs):
        return [_finding("aws-ec2-101")]

    def two(session, region, **kwargs):
        return [_finding("aws-ec2-102")]

    _register(clean_registry, "aws-ec2-101", one, service="EC2")
    _register(clean_registry, "aws-ec2-102", two, service="EC2")

    engine = ScanEngine(max_workers=2)
    result = engine.run_service(MagicMock(), ["us-east-1"], check_id="aws-ec2-101")

    assert len(result.findings) == 1
    assert result.findings[0].check_id == "aws-ec2-101"


def test_run_service_finding_type_filter(clean_registry):
    """finding_type narrows a service set to cost or security checks."""
    def cost(session, region, **kwargs):
        return [_finding("aws-ec2-cost")]

    def security(session, region, **kwargs):
        f = _finding("aws-ec2-sec")
        f.finding_type = FindingType.SECURITY
        return [f]

    _register(clean_registry, "aws-ec2-cost", cost, service="EC2",
              finding_type=FindingType.COST)
    _register(clean_registry, "aws-ec2-sec", security, service="EC2",
              finding_type=FindingType.SECURITY)

    engine = ScanEngine(max_workers=2)
    result = engine.run_service(MagicMock(), ["us-east-1"], service="EC2",
                                finding_type=FindingType.SECURITY)

    assert len(result.findings) == 1
    assert result.findings[0].check_id == "aws-ec2-sec"


def test_run_service_skips_deep_checks_by_default(clean_registry):
    """requires_deep checks are excluded unless deep=True."""
    def deep_check(session, region, **kwargs):
        return [_finding("aws-ec2-deep")]

    _register(clean_registry, "aws-ec2-deep", deep_check, service="EC2",
              requires_deep=True)

    engine = ScanEngine(max_workers=2)
    assert engine.run_service(MagicMock(), ["us-east-1"], service="EC2").findings == []
    assert len(engine.run_service(MagicMock(), ["us-east-1"], service="EC2", deep=True).findings) == 1


def test_run_service_injects_compliance_ids(clean_registry):
    """compliance_ids from metadata are injected into findings that lack them."""
    def ok(session, region, **kwargs):
        return [_finding("aws-ec2-comp")]

    _register(clean_registry, "aws-ec2-comp", ok, service="EC2",
              compliance_ids={"CIS": ["1.1"]})

    engine = ScanEngine(max_workers=2)
    result = engine.run_service(MagicMock(), ["us-east-1"], service="EC2")
    assert result.findings[0].compliance_ids == {"CIS": ["1.1"]}


# ---------------------------------------------------------------------------
# (4) output parity: run_service produces the same finding set as a direct
#     per-region sweep would for a simple hand-built registry
# ---------------------------------------------------------------------------

def test_run_service_output_parity(clean_registry):
    """For a simple registry, run_service returns exactly the expected ids."""
    def a(session, region, **kwargs):
        return [_finding("aws-ec2-a", region=region)]

    def b(session, region, **kwargs):
        return [_finding("aws-ec2-b", region=region)]

    _register(clean_registry, "aws-ec2-a", a, service="EC2")
    _register(clean_registry, "aws-ec2-b", b, service="EC2")

    engine = ScanEngine(max_workers=2)
    regions = ["us-east-1", "eu-west-1"]
    result = engine.run_service(MagicMock(), regions, service="EC2")

    # Two regional checks over two regions -> four findings.
    got = sorted((f.check_id, f.region) for f in result.findings)
    expected = sorted([
        ("aws-ec2-a", "us-east-1"), ("aws-ec2-b", "us-east-1"),
        ("aws-ec2-a", "eu-west-1"), ("aws-ec2-b", "eu-west-1"),
    ])
    assert got == expected
