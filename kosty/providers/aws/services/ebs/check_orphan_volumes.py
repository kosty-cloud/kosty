from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-ebs-001", service="EBS", provider="aws", finding_type=FindingType.COST, description="Find detached EBS volumes")
def check_orphan_volumes(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag volumes in 'available' state — not attached to any instance."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        volumes = ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])
        for vol in volumes['Volumes']:
            if excluded_by_tags(vol, kwargs):
                continue
            name = next((t['Value'] for t in vol.get('Tags', []) if t['Key'] == 'Name'), vol['VolumeId'])
            findings.append(Finding(
                check_id="aws-ebs-001", service="EBS",
                resource_id=vol['VolumeId'], resource_name=name,
                region=region, account_id=account_id,
                issue=f"Orphaned volume ({vol['Size']}GB {vol['VolumeType']})",
                severity=Severity.HIGH, finding_type=FindingType.COST,
                risk=f"~${vol['Size'] * 0.10:.2f}/mo wasted",
                monthly_savings=vol['Size'] * 0.10,
            ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
