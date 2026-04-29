from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-backup-002", service="Backup", provider="aws", finding_type=FindingType.COST, description="Find cross-region backup for dev/test environments")
def check_cross_region_backup_dev_test(session, region, **kwargs):
    """Flag cross-region backup plans on non-production resources."""
    backup = session.client('backup', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        plans = backup.list_backup_plans().get('BackupPlansList', [])
        for plan in plans:
            plan_name = plan.get('BackupPlanName', '').lower()
            is_dev = any(k in plan_name for k in ['dev', 'test', 'staging', 'sandbox'])
            if not is_dev:
                continue
            try:
                detail = backup.get_backup_plan(BackupPlanId=plan['BackupPlanId'])
                rules = detail.get('BackupPlan', {}).get('Rules', [])
                for rule in rules:
                    if rule.get('CopyActions'):
                        findings.append(Finding(
                            check_id="aws-backup-002", service="Backup",
                            resource_id=plan.get('BackupPlanName', ''),
                            region=region, account_id=account_id,
                            issue="Cross-region backup on dev/test environment",
                            severity=Severity.MEDIUM, finding_type=FindingType.COST,
                            risk="Unnecessary replication cost for non-production data",
                        ))
                        break
            except Exception:
                continue
    except Exception:
        pass
    return findings
