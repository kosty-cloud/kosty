from datetime import datetime, timedelta, timezone
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-sagemaker-003", service="SageMaker", provider="aws", finding_type=FindingType.COST, description="Find training jobs not using Spot instances")
def check_no_spot_training(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag long training jobs paying full On-Demand price."""
    sm = session.client('sagemaker', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        jobs = sm.list_training_jobs(CreationTimeAfter=cutoff, StatusEquals='Completed', SortBy='CreationTime', SortOrder='Descending', MaxResults=20)
        for job in jobs.get('TrainingJobSummaries', []):
            try:
                detail = sm.describe_training_job(TrainingJobName=job['TrainingJobName'])
                duration = detail.get('TrainingTimeInSeconds', 0)
                if not detail.get('EnableManagedSpotTraining', False) and duration > 3600:
                    findings.append(Finding(
                        check_id="aws-sagemaker-003", service="SageMaker",
                        resource_id=job['TrainingJobName'], region=region, account_id=account_id,
                        issue=f"Training ran {duration // 3600}h without Spot",
                        severity=Severity.MEDIUM, finding_type=FindingType.COST,
                        risk="Up to 90% savings with managed Spot training",
                        arn=job.get('TrainingJobArn', ''),
                    ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
