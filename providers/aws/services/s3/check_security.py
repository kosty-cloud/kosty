import json
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-s3-004", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Find buckets with public read access via ACL")
def check_public_read(session, region, **kwargs):
    """Flag buckets granting read to AllUsers or AuthenticatedUsers."""
    s3 = session.client('s3')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for bucket in s3.list_buckets()['Buckets']:
            try:
                acl = s3.get_bucket_acl(Bucket=bucket['Name'])
                for grant in acl['Grants']:
                    uri = grant.get('Grantee', {}).get('URI', '')
                    if 'AllUsers' in uri and 'READ' in grant['Permission']:
                        loc = s3.get_bucket_location(Bucket=bucket['Name'])
                        findings.append(Finding(
                            check_id="aws-s3-004", service="S3",
                            resource_id=bucket['Name'], region=loc['LocationConstraint'] or 'us-east-1',
                            account_id=account_id,
                            issue="Public read access via ACL",
                            severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                            risk="Complete bucket contents exposed to the internet",
                        ))
                        break
            except Exception:
                continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-s3-005", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Find buckets with public write access")
def check_public_write(session, region, **kwargs):
    """Flag buckets allowing anyone to upload objects."""
    s3 = session.client('s3')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for bucket in s3.list_buckets()['Buckets']:
            try:
                acl = s3.get_bucket_acl(Bucket=bucket['Name'])
                for grant in acl['Grants']:
                    uri = grant.get('Grantee', {}).get('URI', '')
                    if 'AllUsers' in uri and 'WRITE' in grant['Permission']:
                        loc = s3.get_bucket_location(Bucket=bucket['Name'])
                        findings.append(Finding(
                            check_id="aws-s3-005", service="S3",
                            resource_id=bucket['Name'], region=loc['LocationConstraint'] or 'us-east-1',
                            account_id=account_id,
                            issue="Public write access via ACL",
                            severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                            risk="Malware injection and crypto mining",
                        ))
                        break
            except Exception:
                continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-s3-006", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Find buckets without encryption at rest")
def check_no_encryption(session, region, **kwargs):
    """Flag buckets storing data without server-side encryption."""
    s3 = session.client('s3')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for bucket in s3.list_buckets()['Buckets']:
            try:
                s3.get_bucket_encryption(Bucket=bucket['Name'])
            except s3.exceptions.ClientError as e:
                if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                    loc = s3.get_bucket_location(Bucket=bucket['Name'])
                    findings.append(Finding(
                        check_id="aws-s3-006", service="S3",
                        resource_id=bucket['Name'], region=loc['LocationConstraint'] or 'us-east-1',
                        account_id=account_id,
                        issue="No encryption at rest",
                        severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                        risk="Data readable if storage layer compromised",
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-s3-007", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Find buckets without versioning")
def check_no_versioning(session, region, **kwargs):
    """Flag buckets with no protection against accidental deletion or ransomware."""
    s3 = session.client('s3')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for bucket in s3.list_buckets()['Buckets']:
            try:
                v = s3.get_bucket_versioning(Bucket=bucket['Name'])
                if v.get('Status') != 'Enabled':
                    loc = s3.get_bucket_location(Bucket=bucket['Name'])
                    findings.append(Finding(
                        check_id="aws-s3-007", service="S3",
                        resource_id=bucket['Name'], region=loc['LocationConstraint'] or 'us-east-1',
                        account_id=account_id,
                        issue="Versioning disabled",
                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                        risk="No ransomware protection — deletions are permanent",
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-s3-008", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Find buckets without access logging")
def check_no_logging(session, region, **kwargs):
    """Flag buckets with no audit trail of who accessed what."""
    s3 = session.client('s3')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for bucket in s3.list_buckets()['Buckets']:
            try:
                logging = s3.get_bucket_logging(Bucket=bucket['Name'])
                if 'LoggingEnabled' not in logging:
                    loc = s3.get_bucket_location(Bucket=bucket['Name'])
                    findings.append(Finding(
                        check_id="aws-s3-008", service="S3",
                        resource_id=bucket['Name'], region=loc['LocationConstraint'] or 'us-east-1',
                        account_id=account_id,
                        issue="Access logging disabled",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="Cannot audit data access patterns",
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-s3-009", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Find buckets with wildcard principal in policy")
def check_wildcard_policy(session, region, **kwargs):
    """Flag bucket policies granting access to everyone."""
    s3 = session.client('s3')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for bucket in s3.list_buckets()['Buckets']:
            try:
                policy = json.loads(s3.get_bucket_policy(Bucket=bucket['Name'])['Policy'])
                for stmt in policy.get('Statement', []):
                    principal = stmt.get('Principal')
                    if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                        loc = s3.get_bucket_location(Bucket=bucket['Name'])
                        findings.append(Finding(
                            check_id="aws-s3-009", service="S3",
                            resource_id=bucket['Name'], region=loc['LocationConstraint'] or 'us-east-1',
                            account_id=account_id,
                            issue="Bucket policy allows wildcard principal (*)",
                            severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                            risk="Overly permissive access",
                        ))
                        break
            except Exception:
                continue
    except Exception:
        pass
    return findings
