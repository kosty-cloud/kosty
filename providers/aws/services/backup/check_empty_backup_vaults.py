from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-backup-001",
    service="Backup",
    provider="aws",
    finding_type=FindingType.COST,
    description="Find empty AWS Backup vaults",
)
def check_empty_backup_vaults(session, region, **kwargs):
    """Flag backup vaults with zero recovery points."""
    backup = session.client('backup', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        vaults = backup.list_backup_vaults().get('BackupVaultList', [])
        for vault in vaults:
            if vault.get('NumberOfRecoveryPoints', 0) == 0:
                findings.append(Finding(
                    check_id="aws-backup-001", service="Backup",
                    resource_id=vault['BackupVaultName'], region=region, account_id=account_id,
                    issue="Empty backup vault (0 recovery points)",
                    severity=Severity.LOW, finding_type=FindingType.COST,
                    risk="Vault exists but protects nothing",
                    arn=vault.get('BackupVaultArn', ''),
                ))
    except Exception:
        pass

    return findings
