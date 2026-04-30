from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-ebs-004", service="EBS", provider="aws", finding_type=FindingType.SECURITY, description="Find unencrypted volumes in use")
def check_unencrypted_in_use(session, region, **kwargs):
    """Flag active volumes storing data without encryption at rest."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        volumes = ec2.describe_volumes(Filters=[
            {'Name': 'status', 'Values': ['in-use']},
            {'Name': 'encrypted', 'Values': ['false']}
        ])
        for vol in volumes['Volumes']:
            instance_id = vol['Attachments'][0]['InstanceId'] if vol['Attachments'] else 'N/A'
            findings.append(Finding(
                check_id="aws-ebs-004", service="EBS",
                resource_id=vol['VolumeId'], region=region, account_id=account_id,
                issue=f"Unencrypted volume attached to {instance_id}",
                severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                risk="Data at rest not protected",
            ))
    except Exception:
        pass
    return findings
