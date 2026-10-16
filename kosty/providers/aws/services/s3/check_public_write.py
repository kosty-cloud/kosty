from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-s3-005", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Find buckets with public write access", region_scope="global")
def check_public_write(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag buckets allowing anyone to upload objects."""
    s3 = session.client('s3')
    account_id = get_account_id(session)
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
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
