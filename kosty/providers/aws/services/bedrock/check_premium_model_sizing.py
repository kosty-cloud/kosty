import time
from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-bedrock-011", service="Bedrock", provider="aws", finding_type=FindingType.COST, description="Detect premium models used for simple tasks", requires_deep=True)
def check_premium_model_for_simple_tasks(session: 'boto3.Session', region: str, days=7, deep=False, **kwargs) -> List[Finding]:
    """Heuristic: flag premium models handling short prompts — likely over-specced."""
    account_id = get_account_id(session)
    findings = []

    if not deep:
        findings.append(Finding(
            check_id="aws-bedrock-011", service="Bedrock",
            resource_id="model-sizing", region=region, account_id=account_id,
            issue="Run with --deep to analyze model usage patterns",
            severity=Severity.INFO, finding_type=FindingType.COST,
            risk="Up to 30% savings by routing simple tasks to lighter models",
        ))
        return findings

    try:
        bedrock = session.client('bedrock', region_name=region)
        logs = session.client('logs', region_name=region)
        config = bedrock.get_model_invocation_logging_configuration()
        log_group = config.get('loggingConfig', {}).get('cloudWatchConfig', {}).get('logGroupName', '')
        if not log_group:
            return findings

        end_ms = int(datetime.utcnow().timestamp() * 1000)
        start_ms = int((datetime.utcnow() - timedelta(days=days)).timestamp() * 1000)
        premium = ['claude-3-5-sonnet', 'claude-3-opus', 'claude-3-sonnet']

        query = logs.start_query(
            logGroupName=log_group, startTime=start_ms, endTime=end_ms,
            queryString="fields modelId, input.inputTokenCount, output.outputTokenCount | stats avg(input.inputTokenCount) as avgIn, avg(output.outputTokenCount) as avgOut, count() as n by modelId | sort n desc | limit 20"
        )
        for _ in range(30):
            time.sleep(1)
            result = logs.get_query_results(queryId=query['queryId'])
            if result['status'] == 'Complete':
                break

        for row in result.get('results', []):
            d = {f['field']: f['value'] for f in row}
            model = d.get('modelId', '').lower()
            avg_in = float(d.get('avgIn', 0) or 0)
            avg_out = float(d.get('avgOut', 0) or 0)
            n = int(d.get('n', 0) or 0)
            if any(m in model for m in premium) and avg_in < 500 and avg_out < 150 and n > 100:
                findings.append(Finding(
                    check_id="aws-bedrock-011", service="Bedrock",
                    resource_id=model, region=region, account_id=account_id,
                    issue=f"Premium model for simple tasks (avg {int(avg_in)} in / {int(avg_out)} out, {n} calls)",
                    severity=Severity.MEDIUM, finding_type=FindingType.COST,
                    risk="Route to Haiku/Titan Lite for 30% savings",
                ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
