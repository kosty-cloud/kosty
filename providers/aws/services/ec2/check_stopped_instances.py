import re
from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-ec2-001", service="EC2", provider="aws", finding_type=FindingType.COST, description="Find instances stopped for 7+ days")
def check_stopped_instances(session, region, days=7, **kwargs):
    """Flag stopped instances still incurring EBS and EIP costs."""
    ec2 = session.client('ec2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        cutoff = datetime.now() - timedelta(days=days)
        instances = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}])
        for res in instances['Reservations']:
            for inst in res['Instances']:
                reason = inst.get('StateTransitionReason', '')
                match = re.search(r'\((.*?)\)', reason)
                if match:
                    try:
                        transition = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S %Z')
                        if transition < cutoff:
                            findings.append(Finding(
                                check_id="aws-ec2-001", service="EC2",
                                resource_id=inst['InstanceId'], region=region, account_id=account_id,
                                issue=f"Stopped for {(datetime.now() - transition).days} days ({inst['InstanceType']})",
                                severity=Severity.HIGH, finding_type=FindingType.COST,
                                risk="EBS volumes still billed while instance is stopped",
                            ))
                    except Exception:
                        continue
    except Exception:
        pass
    return findings
