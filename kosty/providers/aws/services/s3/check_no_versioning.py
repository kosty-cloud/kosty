from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-s3-007", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Find buckets without versioning", region_scope="global")
def check_no_versioning(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag buckets with no protection against accidental deletion or ransomware."""
    s3 = session.client('s3')
    account_id = get_account_id(session)
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
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
