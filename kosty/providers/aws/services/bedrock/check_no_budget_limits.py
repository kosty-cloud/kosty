from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-bedrock-002", service="Bedrock", provider="aws", finding_type=FindingType.COST, description="Check if AWS Budget exists for Bedrock spend")
def check_no_budget_limits(session, region, **kwargs):
    """Flag accounts with no spend guardrail on GenAI usage."""
    budgets = session.client('budgets', region_name='us-east-1')
    account_id = get_account_id(session)
    findings = []
    try:
        resp = budgets.describe_budgets(AccountId=account_id)
        has_bedrock = any(
            'bedrock' in b.get('BudgetName', '').lower() or
            any('bedrock' in str(f).lower() for f in b.get('CostFilters', {}).values())
            for b in resp.get('Budgets', [])
        )
        if not has_bedrock:
            findings.append(Finding(
                check_id="aws-bedrock-002", service="Bedrock",
                resource_id="bedrock-budget", region=region, account_id=account_id,
                issue="No AWS Budget for Bedrock spend",
                severity=Severity.HIGH, finding_type=FindingType.COST,
                risk="Stolen API key = unlimited GenAI spend with no alert",
            ))
    except Exception:
        pass
    return findings
