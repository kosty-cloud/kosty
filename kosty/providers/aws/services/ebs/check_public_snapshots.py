from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-ebs-005", service="EBS", provider="aws", finding_type=FindingType.SECURITY, description="Find public EBS snapshots")
def check_public_snapshots(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag snapshots shared with all AWS accounts."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for snap in ec2.describe_snapshots(OwnerIds=[account_id])['Snapshots']:
            if excluded_by_tags(snap, kwargs):
                continue
            try:
                attrs = ec2.describe_snapshot_attribute(SnapshotId=snap['SnapshotId'], Attribute='createVolumePermission')
                if any(p.get('Group') == 'all' for p in attrs.get('CreateVolumePermissions', [])):
                    findings.append(Finding(
                        check_id="aws-ebs-005", service="EBS",
                        resource_id=snap['SnapshotId'], region=region, account_id=account_id,
                        issue="Public snapshot — anyone can copy this data",
                        severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                        risk="Complete volume data exposed to any AWS account",
                    ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
