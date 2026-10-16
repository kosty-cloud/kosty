from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-sagemaker-004", service="SageMaker", provider="aws", finding_type=FindingType.COST, description="Find Spot training jobs without checkpointing")
def check_no_checkpointing(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag Spot jobs that lose all progress on preemption."""
    sm = session.client('sagemaker', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        cutoff = datetime.utcnow() - timedelta(days=30)
        jobs = sm.list_training_jobs(CreationTimeAfter=cutoff, StatusEquals='Completed', SortBy='CreationTime', SortOrder='Descending', MaxResults=20)
        for job in jobs.get('TrainingJobSummaries', []):
            try:
                detail = sm.describe_training_job(TrainingJobName=job['TrainingJobName'])
                if detail.get('EnableManagedSpotTraining', False):
                    if not detail.get('CheckpointConfig', {}).get('S3Uri'):
                        findings.append(Finding(
                            check_id="aws-sagemaker-004", service="SageMaker",
                            resource_id=job['TrainingJobName'], region=region, account_id=account_id,
                            issue="Spot training without checkpointing",
                            severity=Severity.HIGH, finding_type=FindingType.COST,
                            risk="Preemption = lost training progress = wasted spend",
                            arn=job.get('TrainingJobArn', ''),
                        ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
