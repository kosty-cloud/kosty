from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-bedrock-001", service="Bedrock", provider="aws", finding_type=FindingType.SECURITY, description="Check if Bedrock model invocation logging is enabled")
def check_no_logging(session, region, **kwargs):
    """Flag accounts with no audit trail on GenAI usage."""
    bedrock = session.client('bedrock', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        config = bedrock.get_model_invocation_logging_configuration()
        lc = config.get('loggingConfig', {})
        has_s3 = bool(lc.get('s3Config', {}).get('bucketName'))
        has_cw = bool(lc.get('cloudWatchConfig', {}).get('logGroupName'))
        if not has_s3 and not has_cw:
            findings.append(Finding(
                check_id="aws-bedrock-001", service="Bedrock",
                resource_id="bedrock-logging", region=region, account_id=account_id,
                issue="Model invocation logging not enabled",
                severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                risk="No audit trail — prompt injection and data leakage go undetected",
            ))
    except Exception:
        pass
    return findings
