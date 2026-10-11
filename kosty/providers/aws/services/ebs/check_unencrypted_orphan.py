from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-ebs-003", service="EBS", provider="aws", finding_type=FindingType.SECURITY, description="Find unencrypted detached volumes")
def check_unencrypted_orphan(session, region, **kwargs):
    """Flag unencrypted volumes sitting detached — data remnants at risk."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        volumes = ec2.describe_volumes(Filters=[
            {'Name': 'status', 'Values': ['available']},
            {'Name': 'encrypted', 'Values': ['false']}
        ])
        for vol in volumes['Volumes']:
            findings.append(Finding(
                check_id="aws-ebs-003", service="EBS",
                resource_id=vol['VolumeId'], region=region, account_id=account_id,
                issue="Unencrypted orphaned volume",
                severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                risk="Data remnants accessible without encryption",
            ))
    except Exception:
        pass
    return findings
