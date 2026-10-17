import time
from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-bedrock-012", service="Bedrock", provider="aws", finding_type=FindingType.COST, description="Detect On-Demand workloads eligible for Batch Inference", requires_deep=True)
def check_on_demand_batch_eligible(session: 'boto3.Session', region: str, days=7, deep=False, **kwargs) -> List[Finding]:
    """Heuristic: flag burst invocation patterns that could use the 50%-cheaper Batch API."""
    account_id = get_account_id(session)
    findings = []

    if not deep:
        findings.append(Finding(
            check_id="aws-bedrock-012", service="Bedrock",
            resource_id="batch-inference", region=region, account_id=account_id,
            issue="Run with --deep to analyze invocation patterns for batch eligibility",
            severity=Severity.INFO, finding_type=FindingType.COST,
            risk="50% savings by switching burst workloads to Batch Inference API",
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

        query = logs.start_query(
            logGroupName=log_group, startTime=start_ms, endTime=end_ms,
            queryString="fields modelId | stats count() as n by modelId, datefloor(@timestamp, 1h) as hour | stats max(n) as peak, avg(n) as avg by modelId | filter peak > avg * 5 | sort peak desc | limit 10"
        )
        for _ in range(30):
            time.sleep(1)
            result = logs.get_query_results(queryId=query['queryId'])
            if result['status'] == 'Complete':
                break

        for row in result.get('results', []):
            d = {f['field']: f['value'] for f in row}
            model = d.get('modelId', '')
            peak = int(d.get('peak', 0) or 0)
            avg = float(d.get('avg', 0) or 0)
            if peak > 50 and avg > 0:
                findings.append(Finding(
                    check_id="aws-bedrock-012", service="Bedrock",
                    resource_id=model, region=region, account_id=account_id,
                    issue=f"Burst pattern ({peak} req/h peak vs {round(avg)} avg) — batch-eligible",
                    severity=Severity.MEDIUM, finding_type=FindingType.COST,
                    risk="Batch Inference API is 50% cheaper for non-real-time workloads",
                ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
