from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-ec2-009", service="EC2", provider="aws", finding_type=FindingType.SECURITY, description="Find instances using AMIs older than 180 days")
def check_old_ami(session, region, days=180, **kwargs):
    """Flag instances running on stale AMIs — unpatched CVEs accumulate."""
    ec2 = session.client('ec2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        cutoff = datetime.now() - timedelta(days=days)
        instances = ec2.describe_instances()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                ami_id = inst.get('ImageId')
                if not ami_id:
                    continue
                try:
                    images = ec2.describe_images(ImageIds=[ami_id])
                    if images['Images']:
                        created = datetime.strptime(images['Images'][0]['CreationDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
                        if created < cutoff:
                            findings.append(Finding(
                                check_id="aws-ec2-009", service="EC2",
                                resource_id=inst['InstanceId'], region=region, account_id=account_id,
                                issue=f"AMI {ami_id} is {(datetime.now() - created).days} days old",
                                severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                                risk="Unpatched CVEs accumulating on stale image",
                            ))
                except Exception:
                    continue
    except Exception:
        pass
    return findings
