from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-ebs-006", service="EBS", provider="aws", finding_type=FindingType.SECURITY, description="Find in-use volumes with no recent snapshot")
def check_no_recent_snapshot(session, region, days=7, **kwargs):
    """Flag volumes without a backup in the last 7 days."""
    ec2 = session.client('ec2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        cutoff = datetime.now() - timedelta(days=days)
        volumes = ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['in-use']}])
        for vol in volumes['Volumes']:
            snaps = ec2.describe_snapshots(
                OwnerIds=[account_id],
                Filters=[{'Name': 'volume-id', 'Values': [vol['VolumeId']]}]
            )
            has_recent = any(
                s['StartTime'].replace(tzinfo=None) > cutoff
                for s in snaps['Snapshots']
            )
            if not has_recent:
                findings.append(Finding(
                    check_id="aws-ebs-006", service="EBS",
                    resource_id=vol['VolumeId'], region=region, account_id=account_id,
                    issue=f"No snapshot in {days}+ days",
                    severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                    risk="No backup — data loss risk",
                ))
    except Exception:
        pass
    return findings
