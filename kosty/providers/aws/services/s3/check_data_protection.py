from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-s3-010", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Find buckets without MFA delete")
def check_no_mfa_delete(session, region, **kwargs):
    """Flag buckets where versioned objects can be deleted without MFA."""
    s3 = session.client('s3')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for bucket in s3.list_buckets()['Buckets']:
            try:
                v = s3.get_bucket_versioning(Bucket=bucket['Name'])
                if v.get('MfaDelete') != 'Enabled':
                    loc = s3.get_bucket_location(Bucket=bucket['Name'])
                    findings.append(Finding(
                        check_id="aws-s3-010", service="S3",
                        resource_id=bucket['Name'], region=loc['LocationConstraint'] or 'us-east-1',
                        account_id=account_id,
                        issue="MFA delete not enabled",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="Accidental or malicious deletion without second factor",
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-s3-011", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Find buckets without Object Lock")
def check_no_object_lock(session, region, **kwargs):
    """Flag buckets without immutability protection."""
    s3 = session.client('s3')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for bucket in s3.list_buckets()['Buckets']:
            try:
                loc = s3.get_bucket_location(Bucket=bucket['Name'])
                bucket_region = loc['LocationConstraint'] or 'us-east-1'
                try:
                    lock = s3.get_object_lock_configuration(Bucket=bucket['Name'])
                    if lock.get('ObjectLockConfiguration', {}).get('ObjectLockEnabled') != 'Enabled':
                        raise Exception()
                except Exception:
                    findings.append(Finding(
                        check_id="aws-s3-011", service="S3",
                        resource_id=bucket['Name'], region=bucket_region, account_id=account_id,
                        issue="Object Lock not enabled",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="No immutability — ransomware can encrypt/delete all versions",
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-s3-012", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Find buckets without cross-region replication")
def check_no_cross_region_replication(session, region, **kwargs):
    """Flag buckets with no DR replication configured."""
    s3 = session.client('s3')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for bucket in s3.list_buckets()['Buckets']:
            try:
                loc = s3.get_bucket_location(Bucket=bucket['Name'])
                bucket_region = loc['LocationConstraint'] or 'us-east-1'
                try:
                    s3.get_bucket_replication(Bucket=bucket['Name'])
                except s3.exceptions.ClientError:
                    findings.append(Finding(
                        check_id="aws-s3-012", service="S3",
                        resource_id=bucket['Name'], region=bucket_region, account_id=account_id,
                        issue="No cross-region replication",
                        severity=Severity.LOW, finding_type=FindingType.SECURITY,
                        risk="No disaster recovery for regional outage",
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-s3-013", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Check account-level S3 Block Public Access", compliance_ids={"CIS": ["2.1.4"]})
def check_no_account_public_access_block(session, region, **kwargs):
    """Flag accounts without the global guardrail against public buckets."""
    account_id = session.client('sts').get_caller_identity()['Account']
    s3control = session.client('s3control', region_name=region)
    findings = []
    try:
        pab = s3control.get_public_access_block(AccountId=account_id)
        config = pab['PublicAccessBlockConfiguration']
        missing = [k for k in ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'] if not config.get(k, False)]
        if missing:
            findings.append(Finding(
                check_id="aws-s3-013", service="S3",
                resource_id="account-public-access-block", region=region, account_id=account_id,
                issue=f"Account Block Public Access incomplete: {', '.join(missing)}",
                severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                risk="New buckets can be made public accidentally",
            ))
    except Exception as e:
        if 'NoSuchPublicAccessBlockConfiguration' in str(e):
            findings.append(Finding(
                check_id="aws-s3-013", service="S3",
                resource_id="account-public-access-block", region=region, account_id=account_id,
                issue="Account Block Public Access not configured",
                severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                risk="No guardrail against public bucket creation",
            ))
    return findings
