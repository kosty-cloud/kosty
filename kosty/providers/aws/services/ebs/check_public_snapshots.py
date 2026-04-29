from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-ebs-005", service="EBS", provider="aws", finding_type=FindingType.SECURITY, description="Find public EBS snapshots")
def check_public_snapshots(session, region, **kwargs):
    """Flag snapshots shared with all AWS accounts."""
    ec2 = session.client('ec2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for snap in ec2.describe_snapshots(OwnerIds=[account_id])['Snapshots']:
            try:
                attrs = ec2.describe_snapshot_attribute(SnapshotId=snap['SnapshotId'], Attribute='createVolumePermission')
                if any(p.get('Group') == 'all' for p in attrs.get('CreateVolumePermissions', [])):
                    findings.append(Finding(
                        check_id="aws-ebs-005", service="EBS",
                        resource_id=snap['SnapshotId'], region=region, account_id=account_id,
                        issue="Public snapshot — anyone can copy this data",
                        severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                        risk="Complete volume data exposed to any AWS account",
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
