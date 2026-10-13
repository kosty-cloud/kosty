from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.services._pricing import rds_monthly
from kosty.core.tag_utils import excluded_by_tags


@register_check(check_id="aws-rds-002", service="RDS", provider="aws", finding_type=FindingType.COST, description="Find oversized RDS instances (<20% CPU)")
def check_oversized_instances(session, region, days=14, cpu_threshold=20, **kwargs):
    """Flag databases consistently underutilizing allocated compute. Skips smallest available instance per engine."""
    rds = session.client('rds', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    account_id = get_account_id(session)
    findings = []
    size_order = ['micro', 'small', 'medium', 'large', 'xlarge', '2xlarge', '4xlarge', '8xlarge', '12xlarge', '16xlarge']
    min_cache = {}
    try:
        end = datetime.utcnow()
        start = end - timedelta(days=days)
        for db in rds.describe_db_instances()['DBInstances']:
            if excluded_by_tags(db, kwargs):
                continue
            if db['DBInstanceStatus'] != 'available':
                continue
            engine, version = db['Engine'], db.get('EngineVersion', '')
            instance_class = db['DBInstanceClass']
            cache_key = f"{engine}:{version}"
            if cache_key not in min_cache:
                try:
                    smallest, smallest_rank = None, 999
                    for page in rds.get_paginator('describe_orderable_db_instance_options').paginate(Engine=engine, EngineVersion=version):
                        for opt in page['OrderableDBInstanceOptions']:
                            size = opt['DBInstanceClass'].split('.')[-1]
                            rank = size_order.index(size) if size in size_order else 999
                            if rank < smallest_rank:
                                smallest_rank, smallest = rank, opt['DBInstanceClass']
                    min_cache[cache_key] = smallest
                except Exception:
                    min_cache[cache_key] = None
            if min_cache[cache_key] and instance_class == min_cache[cache_key]:
                continue
            try:
                metrics = cw.get_metric_statistics(
                    Namespace='AWS/RDS', MetricName='CPUUtilization',
                    Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db['DBInstanceIdentifier']}],
                    StartTime=start, EndTime=end, Period=3600, Statistics=['Average']
                )
                if metrics['Datapoints']:
                    avg = sum(dp['Average'] for dp in metrics['Datapoints']) / len(metrics['Datapoints'])
                    if avg < cpu_threshold:
                        # Downsizing one class saves roughly 50% — conservative estimate
                        savings = round(rds_monthly(instance_class) * 0.5, 2)
                        findings.append(Finding(
                            check_id="aws-rds-002", service="RDS",
                            resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                            issue=f"Oversized ({round(avg, 1)}% CPU, {instance_class})",
                            severity=Severity.HIGH, finding_type=FindingType.COST,
                            risk="30-60% waste — downsize to next smaller class",
                            arn=db['DBInstanceArn'],
                            monthly_savings=savings,
                            details={'instance_class': instance_class, 'avg_cpu': round(avg, 1)},
                        ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
