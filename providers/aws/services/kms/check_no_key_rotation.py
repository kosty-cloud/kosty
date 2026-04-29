from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-kms-001",
    service="KMS",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find customer-managed keys without automatic rotation",
)
def check_no_key_rotation(session, region, **kwargs):
    """Flag symmetric CMKs without annual rotation enabled."""
    kms = session.client('kms', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        paginator = kms.get_paginator('list_keys')
        for page in paginator.paginate():
            for key in page['Keys']:
                try:
                    meta = kms.describe_key(KeyId=key['KeyId'])['KeyMetadata']
                    if meta.get('KeyManager') != 'CUSTOMER' or meta.get('KeyState') != 'Enabled':
                        continue
                    if meta.get('KeySpec') != 'SYMMETRIC_DEFAULT':
                        continue

                    rotation = kms.get_key_rotation_status(KeyId=key['KeyId'])
                    if not rotation.get('KeyRotationEnabled'):
                        alias = ''
                        try:
                            aliases = kms.list_aliases(KeyId=key['KeyId'])
                            if aliases['Aliases']:
                                alias = aliases['Aliases'][0]['AliasName']
                        except Exception:
                            pass
                        findings.append(Finding(
                            check_id="aws-kms-001", service="KMS",
                            resource_id=alias or key['KeyId'],
                            region=region, account_id=account_id,
                            issue="Automatic key rotation not enabled",
                            severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                            risk="Long-lived keys increase exposure if compromised",
                            arn=meta['Arn'],
                        ))
                except Exception:
                    continue
    except Exception:
        pass

    return findings
