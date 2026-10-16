from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-ec2-004", service="EC2", provider="aws", finding_type=FindingType.COST, description="Find previous generation instance types")
def check_previous_generation(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag instances on old families (t2, m4, c4, etc.) — 10-20% more expensive than current gen."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    previous_gen = ['t2', 'm4', 'c4', 'r4', 'm3', 'c3', 'r3', 't1', 'm1', 'c1']
    try:
        instances = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}])
        for res in instances['Reservations']:
            for inst in res['Instances']:
                if excluded_by_tags(inst, kwargs):
                    continue
                family = inst['InstanceType'].split('.')[0]
                if family in previous_gen:
                    findings.append(Finding(
                        check_id="aws-ec2-004", service="EC2",
                        resource_id=inst['InstanceId'], region=region, account_id=account_id,
                        issue=f"Previous generation ({inst['InstanceType']})",
                        severity=Severity.MEDIUM, finding_type=FindingType.COST,
                        risk="10-20% more expensive than current gen equivalent",
                    ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
