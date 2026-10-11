from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-s3-001", service="S3", provider="aws", finding_type=FindingType.COST, description="Find empty S3 buckets", region_scope="global")
def check_empty_buckets(session, region, **kwargs):
    """Flag buckets with zero objects."""
    s3 = session.client('s3')
    account_id = get_account_id(session)
    findings = []
    try:
        for bucket in s3.list_buckets()['Buckets']:
            try:
                objects = s3.list_objects_v2(Bucket=bucket['Name'], MaxKeys=1)
                if 'Contents' not in objects:
                    loc = s3.get_bucket_location(Bucket=bucket['Name'])
                    bucket_region = loc['LocationConstraint'] or 'us-east-1'
                    findings.append(Finding(
                        check_id="aws-s3-001", service="S3",
                        resource_id=bucket['Name'], region=bucket_region, account_id=account_id,
                        issue="Empty bucket",
                        severity=Severity.LOW, finding_type=FindingType.COST,
                        risk="Minimal cost but adds clutter",
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-s3-002", service="S3", provider="aws", finding_type=FindingType.COST, description="Find incomplete multipart uploads", region_scope="global")
def check_incomplete_uploads(session, region, **kwargs):
    """Flag buckets with abandoned multipart uploads consuming storage."""
    s3 = session.client('s3')
    account_id = get_account_id(session)
    findings = []
    try:
        for bucket in s3.list_buckets()['Buckets']:
            try:
                uploads = s3.list_multipart_uploads(Bucket=bucket['Name'])
                if uploads.get('Uploads'):
                    loc = s3.get_bucket_location(Bucket=bucket['Name'])
                    bucket_region = loc['LocationConstraint'] or 'us-east-1'
                    findings.append(Finding(
                        check_id="aws-s3-002", service="S3",
                        resource_id=bucket['Name'], region=bucket_region, account_id=account_id,
                        issue=f"{len(uploads['Uploads'])} incomplete multipart uploads",
                        severity=Severity.MEDIUM, finding_type=FindingType.COST,
                        risk="Hidden storage cost from abandoned uploads",
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-s3-003", service="S3", provider="aws", finding_type=FindingType.COST, description="Find buckets without lifecycle policy", region_scope="global")
def check_no_lifecycle(session, region, **kwargs):
    """Flag buckets with data but no expiration or transition rules."""
    s3 = session.client('s3')
    account_id = get_account_id(session)
    findings = []
    try:
        for bucket in s3.list_buckets()['Buckets']:
            try:
                loc = s3.get_bucket_location(Bucket=bucket['Name'])
                bucket_region = loc['LocationConstraint'] or 'us-east-1'
                try:
                    s3.get_bucket_lifecycle_configuration(Bucket=bucket['Name'])
                except s3.exceptions.ClientError:
                    objects = s3.list_objects_v2(Bucket=bucket['Name'], MaxKeys=1)
                    if 'Contents' in objects:
                        findings.append(Finding(
                            check_id="aws-s3-003", service="S3",
                            resource_id=bucket['Name'], region=bucket_region, account_id=account_id,
                            issue="No lifecycle policy on bucket with data",
                            severity=Severity.HIGH, finding_type=FindingType.COST,
                            risk="50-70% savings possible with tiering/expiration",
                        ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
