from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags


@register_check(check_id="aws-ebs-002", service="EBS", provider="aws", finding_type=FindingType.COST, description="Find gp2 volumes (should be gp3)")
def check_gp2_volumes(session, region, **kwargs):
    """Flag gp2 volumes — gp3 is 20% cheaper with same baseline performance."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        volumes = ec2.describe_volumes(Filters=[{'Name': 'volume-type', 'Values': ['gp2']}])
        for vol in volumes['Volumes']:
            if excluded_by_tags(vol, kwargs):
                continue
            findings.append(Finding(
                check_id="aws-ebs-002", service="EBS",
                resource_id=vol['VolumeId'], region=region, account_id=account_id,
                issue=f"gp2 volume ({vol['Size']}GB) — migrate to gp3 for 20% savings",
                severity=Severity.MEDIUM, finding_type=FindingType.COST,
                risk="20% overpaying vs gp3",
                monthly_savings=vol['Size'] * 0.10 * 0.20,
            ))
    except Exception:
        pass
    return findings
