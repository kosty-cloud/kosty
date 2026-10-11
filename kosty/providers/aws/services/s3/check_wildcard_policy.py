import json
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-s3-009", service="S3", provider="aws", finding_type=FindingType.SECURITY, description="Find buckets with wildcard principal in policy", region_scope="global")
def check_wildcard_policy(session, region, **kwargs):
    """Flag bucket policies granting access to everyone."""
    s3 = session.client('s3')
    account_id = get_account_id(session)
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
