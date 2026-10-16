import re
from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.services._pricing import ec2_monthly
from kosty.core.tag_utils import excluded_by_tags
from kosty.core.config import resolve_threshold
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-ec2-001", service="EC2", provider="aws", finding_type=FindingType.COST, description="Find instances stopped for 7+ days")
def check_stopped_instances(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag stopped instances still incurring EBS and EIP costs."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    days = resolve_threshold(kwargs, 'days', 'stopped_days', 7)
    findings = []
    try:
        cutoff = datetime.now() - timedelta(days=days)
        instances = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}])
        for res in instances['Reservations']:
            for inst in res['Instances']:
                if excluded_by_tags(inst, kwargs):
                    continue
                reason = inst.get('StateTransitionReason', '')
                match = re.search(r'\((.*?)\)', reason)
                if match:
                    try:
                        transition = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S %Z')
                        if transition < cutoff:
                            instance_type = inst['InstanceType']
                            findings.append(Finding(
                                check_id="aws-ec2-001", service="EC2",
                                resource_id=inst['InstanceId'], region=region, account_id=account_id,
                                issue=f"Stopped for {(datetime.now() - transition).days} days ({instance_type})",
                                severity=Severity.HIGH, finding_type=FindingType.COST,
                                risk="EBS volumes still billed while instance is stopped",
                                monthly_savings=ec2_monthly(instance_type),
                                details={'instance_type': instance_type},
                            ))
                    except Exception as _exc:
                        handle_check_error(_exc)
                        continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
