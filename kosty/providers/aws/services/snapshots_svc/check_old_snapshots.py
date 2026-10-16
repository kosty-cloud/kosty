from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags
from kosty.core.config import resolve_threshold


@register_check(
    check_id="aws-snapshots-001",
    service="Snapshots",
    provider="aws",
    finding_type=FindingType.COST,
    description="Find EBS snapshots older than old_snapshot_days (default 30)",
)
def check_old_snapshots(session, region, **kwargs):
    """Flag snapshots accumulating storage costs with no recent use."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    days = resolve_threshold(kwargs, 'days', 'old_snapshot_days', 30)
    findings = []

    try:
        cutoff = datetime.now() - timedelta(days=days)
        for snap in ec2.describe_snapshots(OwnerIds=[account_id])['Snapshots']:
            if excluded_by_tags(snap, kwargs):
                continue
            start_time = snap['StartTime'].replace(tzinfo=None)
            if start_time < cutoff:
                findings.append(Finding(
                    check_id="aws-snapshots-001", service="Snapshots",
                    resource_id=snap['SnapshotId'], region=region, account_id=account_id,
                    issue=f"Snapshot older than {days} days ({(datetime.now() - start_time).days}d)",
                    severity=Severity.LOW, finding_type=FindingType.COST,
                    risk="$0.05/GB/mo storage cost accumulating",
                    monthly_savings=snap['VolumeSize'] * 0.05,
                ))
    except Exception:
        pass

    return findings
