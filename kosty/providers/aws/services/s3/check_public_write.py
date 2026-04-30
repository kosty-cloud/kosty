import json
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-s3-005", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Find buckets with public write access")
def check_public_write(session, region, **kwargs):
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
            except Exception:
                continue
    except Exception:
        pass
    return findings
