from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-ebs-007", service="EBS", provider="aws", finding_type=FindingType.COST, description="Find volumes with very low I/O")
def check_low_io_volumes(session: 'boto3.Session', region: str, days=7, iops_threshold=10, **kwargs) -> List[Finding]:
    """Flag in-use volumes barely doing any I/O — likely oversized."""
    ec2 = session.client('ec2', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        end = datetime.utcnow()
        start = end - timedelta(days=days)
        volumes = ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['in-use']}])
        for vol in volumes['Volumes']:
            if excluded_by_tags(vol, kwargs):
                continue
            try:
                read_ops = cw.get_metric_statistics(
                    Namespace='AWS/EBS', MetricName='VolumeReadOps',
                    Dimensions=[{'Name': 'VolumeId', 'Value': vol['VolumeId']}],
                    StartTime=start, EndTime=end, Period=3600, Statistics=['Sum']
                )
                write_ops = cw.get_metric_statistics(
                    Namespace='AWS/EBS', MetricName='VolumeWriteOps',
                    Dimensions=[{'Name': 'VolumeId', 'Value': vol['VolumeId']}],
                    StartTime=start, EndTime=end, Period=3600, Statistics=['Sum']
                )
                total = sum(dp['Sum'] for dp in read_ops.get('Datapoints', [])) + sum(dp['Sum'] for dp in write_ops.get('Datapoints', []))
                iops_per_gb = (total / (days * 24)) / vol['Size'] if vol['Size'] > 0 else 0

                if iops_per_gb < iops_threshold:
                    findings.append(Finding(
                        check_id="aws-ebs-007", service="EBS",
                        resource_id=vol['VolumeId'], region=region, account_id=account_id,
                        issue=f"Low I/O volume ({round(iops_per_gb, 1)} IOPS/GB)",
                        severity=Severity.MEDIUM, finding_type=FindingType.COST,
                        risk="Oversized — consider smaller volume or downgrade type",
                    ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
