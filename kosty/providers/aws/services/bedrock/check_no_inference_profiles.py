from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-bedrock-008", service="Bedrock", provider="aws", finding_type=FindingType.COST, description="Check if Application Inference Profiles are configured")
def check_no_inference_profiles(session, region, **kwargs):
    """Flag accounts with no cost attribution mechanism for GenAI spend."""
    bedrock = session.client('bedrock', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        profiles = bedrock.list_inference_profiles()
        if not profiles.get('inferenceProfileSummaries', []):
            findings.append(Finding(
                check_id="aws-bedrock-008", service="Bedrock",
                resource_id="inference-profiles", region=region, account_id=account_id,
                issue="No Application Inference Profiles configured",
                severity=Severity.LOW, finding_type=FindingType.COST,
                risk="Cannot attribute token spend per team or project",
            ))
    except Exception:
        pass
    return findings
