from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-bedrock-009", service="Bedrock", provider="aws", finding_type=FindingType.COST, description="Check if TPM quota usage is above 80%")
def check_tpm_quota_high_usage(session: 'boto3.Session', region: str, threshold=80, **kwargs) -> List[Finding]:
    """Flag models approaching throttling limits."""
    sq = session.client('service-quotas', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for page in sq.get_paginator('list_service_quotas').paginate(ServiceCode='bedrock'):
            for quota in page['Quotas']:
                if 'token' not in quota.get('QuotaName', '').lower():
                    continue
                value = quota.get('Value', 0)
                usage = quota.get('UsageMetric', {})
                if not value or not usage:
                    continue
                try:
                    cw = session.client('cloudwatch', region_name=region)
                    metrics = cw.get_metric_statistics(
                        Namespace=usage.get('MetricNamespace', ''),
                        MetricName=usage.get('MetricName', ''),
                        Dimensions=[{'Name': k, 'Value': v} for k, v in usage.get('MetricDimensions', {}).items()],
                        StartTime=datetime.utcnow() - timedelta(hours=24),
                        EndTime=datetime.utcnow(), Period=3600, Statistics=['Maximum']
                    )
                    if metrics['Datapoints']:
                        peak = max(dp['Maximum'] for dp in metrics['Datapoints'])
                        pct = (peak / value) * 100
                        if pct >= threshold:
                            findings.append(Finding(
                                check_id="aws-bedrock-009", service="Bedrock",
                                resource_id=quota['QuotaName'], region=region, account_id=account_id,
                                issue=f"TPM quota at {round(pct)}%",
                                severity=Severity.HIGH if pct >= 90 else Severity.MEDIUM,
                                finding_type=FindingType.COST,
                                risk="Approaching throttling — production requests will be rejected",
                            ))
                except Exception as _exc:
                    handle_check_error(_exc)
                    continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
