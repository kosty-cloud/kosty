from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-bedrock-007", service="Bedrock", provider="aws", finding_type=FindingType.COST, description="Check if prompt caching is being used")
def check_no_prompt_caching(session, region, **kwargs):
    """Flag accounts with cache-compatible models but no caching verified."""
    bedrock = session.client('bedrock', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        models = bedrock.list_foundation_models()
        compatible = [m for m in models.get('modelSummaries', [])
                      if 'anthropic' in m.get('providerName', '').lower() or 'amazon' in m.get('providerName', '').lower()]
        if compatible:
            findings.append(Finding(
                check_id="aws-bedrock-007", service="Bedrock",
                resource_id="prompt-caching", region=region, account_id=account_id,
                issue=f"{len(compatible)} cache-compatible models — verify caching is enabled in your app",
                severity=Severity.MEDIUM, finding_type=FindingType.COST,
                risk="Up to 90% savings on repeated system prompts if caching enabled",
            ))
    except Exception:
        pass
    return findings
