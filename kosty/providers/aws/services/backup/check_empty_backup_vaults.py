from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(
    check_id="aws-backup-001",
    service="Backup",
    provider="aws",
    finding_type=FindingType.COST,
    description="Find empty AWS Backup vaults",
)
def check_empty_backup_vaults(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag backup vaults with zero recovery points."""
    backup = session.client('backup', region_name=region)
    account_id = get_account_id(session)
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
    except Exception as _exc:
        handle_check_error(_exc)

    return findings
