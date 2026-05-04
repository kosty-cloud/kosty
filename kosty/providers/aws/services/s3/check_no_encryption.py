from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-s3-006", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Find buckets without encryption at rest", region_scope="global")
def check_no_encryption(session, region, **kwargs):
    """Flag buckets storing data without server-side encryption."""
    s3 = session.client('s3')
    account_id = get_account_id(session)
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
