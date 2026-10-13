from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags


@register_check(check_id="aws-rds-003", service="RDS", provider="aws", finding_type=FindingType.COST, description="Find unused read replicas")
def check_unused_read_replicas(session, region, days=7, **kwargs):
    """Flag replicas with near-zero read traffic."""
    rds = session.client('rds', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        end = datetime.utcnow()
        start = end - timedelta(days=days)
        for db in rds.describe_db_instances()['DBInstances']:
            if excluded_by_tags(db, kwargs):
                continue
            if not db.get('ReadReplicaSourceDBInstanceIdentifier'):
                continue
            try:
                metrics = cw.get_metric_statistics(
                    Namespace='AWS/RDS', MetricName='ReadIOPS',
                    Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db['DBInstanceIdentifier']}],
                    StartTime=start, EndTime=end, Period=86400, Statistics=['Sum']
                )
                total = sum(dp['Sum'] for dp in metrics['Datapoints']) if metrics['Datapoints'] else 0
                if total / max(days, 1) < 100:
                    findings.append(Finding(
                        check_id="aws-rds-003", service="RDS",
                        resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                        issue="Unused read replica (<100 reads/day)",
                        severity=Severity.HIGH, finding_type=FindingType.COST,
                        risk="$100-500/mo for a replica nobody reads from", arn=db['DBInstanceArn'],
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
