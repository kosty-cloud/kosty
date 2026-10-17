from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags
from kosty.core.config import resolve_threshold
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-ec2-009", service="EC2", provider="aws", finding_type=FindingType.SECURITY, description="Find instances using AMIs older than 180 days")
def check_old_ami(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag instances running on stale AMIs — unpatched CVEs accumulate."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    days = resolve_threshold(kwargs, 'days', 'ami_days', 180)
    findings = []
    try:
        cutoff = datetime.now() - timedelta(days=days)
        instances = ec2.describe_instances()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                if excluded_by_tags(inst, kwargs):
                    continue
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
                except Exception as _exc:
                    handle_check_error(_exc)
                    continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
