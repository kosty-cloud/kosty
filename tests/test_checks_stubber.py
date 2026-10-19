"""Offline check tests driven by botocore.stub.Stubber.

Stubber ships with botocore (the official AWS SDK core), so these tests parse
real boto3 response shapes through the real check functions without any live
AWS call, STS call, or network I/O and without adding a runtime dependency
(no moto). Each stubbed payload mirrors the minimal valid shape of the API the
check actually calls, learned by reading the check source first:

- EBS orphan-volume cost check  -> ec2.describe_volumes
- SG open-port security check   -> ec2.describe_security_groups
- Bedrock guardrails check       -> bedrock.list_guardrails (AccessDenied path)

The account id is resolved by session_utils.get_account_id via an STS
get_caller_identity call, so every scenario also stubs STS. The session is a
MagicMock whose .client(service, ...) returns the matching stubbed client, so
the proxy/engine path stays entirely in-process.
"""

import boto3
import pytest
from botocore.stub import Stubber
from unittest.mock import MagicMock

from kosty.core.engine import ScanEngine
from kosty.core.models import FindingType
from kosty.providers.aws import session_utils


REGION = "us-east-1"
ACCOUNT_ID = "123456789012"


@pytest.fixture(autouse=True)
def _clear_account_cache():
    """Reset the shared get_account_id cache so each scenario is isolated."""
    session_utils._cache.clear()
    yield
    session_utils._cache.clear()


def _sts_stub():
    """Return (client, Stubber) for an STS get_caller_identity returning ACCOUNT_ID."""
    client = boto3.client("sts", region_name=REGION,
                          aws_access_key_id="x", aws_secret_access_key="y")
    stub = Stubber(client)
    stub.add_response("get_caller_identity", {"Account": ACCOUNT_ID,
                                              "UserId": "AIDA", "Arn": "arn:aws:iam::x:user/x"})
    return client, stub


def _dispatch_session(clients):
    """Build a MagicMock session whose .client(service, ...) returns a stub client.

    clients maps a service name ('ec2', 'sts', ...) to the real stubbed client.
    Extra kwargs (e.g. the config= injected by the timeout proxy) are ignored.
    """
    session = MagicMock()

    def _client(service, *args, **kwargs):
        return clients[service]

    session.client.side_effect = _client
    return session


# ---------------------------------------------------------------------------
# (1) COST: an orphaned EBS volume yields a Finding with positive savings
# ---------------------------------------------------------------------------

def test_ebs_orphan_volume_cost_finding():
    """A stubbed available volume produces a cost Finding with monthly_savings."""
    from kosty.providers.aws.services.ebs.check_orphan_volumes import check_orphan_volumes

    ec2 = boto3.client("ec2", region_name=REGION,
                       aws_access_key_id="x", aws_secret_access_key="y")
    ec2_stub = Stubber(ec2)
    ec2_stub.add_response(
        "describe_volumes",
        {"Volumes": [{
            "VolumeId": "vol-0abc",
            "Size": 100,
            "VolumeType": "gp3",
            "State": "available",
            "Tags": [{"Key": "Name", "Value": "leftover"}],
        }]},
        {"Filters": [{"Name": "status", "Values": ["available"]}]},
    )
    sts, sts_stub = _sts_stub()
    session = _dispatch_session({"ec2": ec2, "sts": sts})

    with ec2_stub, sts_stub:
        findings = check_orphan_volumes(session=session, region=REGION)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == FindingType.COST
    assert finding.resource_id == "vol-0abc"
    assert finding.monthly_savings == pytest.approx(100 * 0.10)
    assert finding.monthly_savings > 0


# ---------------------------------------------------------------------------
# (2) SECURITY: an SSH-open security group yields a security Finding
# ---------------------------------------------------------------------------

def test_sg_open_ssh_security_finding():
    """A stubbed SG with port 22 open to 0.0.0.0/0 produces a security Finding."""
    from kosty.providers.aws.services.sg.check_security_groups import check_ssh_rdp_open

    ec2 = boto3.client("ec2", region_name=REGION,
                       aws_access_key_id="x", aws_secret_access_key="y")
    ec2_stub = Stubber(ec2)
    ec2_stub.add_response(
        "describe_security_groups",
        {"SecurityGroups": [{
            "GroupId": "sg-0abc",
            "GroupName": "web",
            "Description": "web sg",
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
            "IpPermissionsEgress": [],
        }]},
    )
    sts, sts_stub = _sts_stub()
    session = _dispatch_session({"ec2": ec2, "sts": sts})

    with ec2_stub, sts_stub:
        findings = check_ssh_rdp_open(session=session, region=REGION)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == FindingType.SECURITY
    assert finding.resource_id == "sg-0abc"
    assert "22" in finding.issue


# ---------------------------------------------------------------------------
# (3) AccessDenied: a permission error is re-raised into ScanResult.errors
# ---------------------------------------------------------------------------

def test_access_denied_surfaces_in_scan_errors():
    """A Bedrock AccessDenied is re-raised by handle_check_error and recorded."""
    # Import the check so it self-registers under its real check_id.
    from kosty.providers.aws.services.bedrock import check_no_guardrails  # noqa: F401

    bedrock = boto3.client("bedrock", region_name=REGION,
                           aws_access_key_id="x", aws_secret_access_key="y")
    bedrock_stub = Stubber(bedrock)
    bedrock_stub.add_client_error(
        "list_guardrails",
        service_error_code="AccessDeniedException",
        service_message="User is not authorized to perform bedrock:ListGuardrails",
        http_status_code=403,
    )
    sts, sts_stub = _sts_stub()
    session = _dispatch_session({"bedrock": bedrock, "sts": sts})

    engine = ScanEngine(max_workers=1)
    with bedrock_stub, sts_stub:
        result = engine.run_service(session, [REGION], check_id="aws-bedrock-003")

    assert result.findings == []
    assert len(result.errors) == 1
    error = result.errors[0]
    assert "aws-bedrock-003" in error
    assert "AccessDeniedException" in error
