from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(
    check_id="aws-nat-001",
    service="NAT",
    provider="aws",
    finding_type=FindingType.COST,
    description="Find NAT Gateways with zero traffic",
)
def check_unused_nat_gateways(session, region, days=7, **kwargs):
    """Flag NAT Gateways processing no bytes over the analysis period."""
    from datetime import datetime, timedelta
    ec2 = session.client('ec2', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        gateways = ec2.describe_nat_gateways(
            Filters=[{'Name': 'state', 'Values': ['available']}]
        )['NatGateways']
        end = datetime.utcnow()
        start = end - timedelta(days=days)

        for gw in gateways:
            try:
                metrics = cw.get_metric_statistics(
                    Namespace='AWS/NATGateway', MetricName='BytesOutToDestination',
                    Dimensions=[{'Name': 'NatGatewayId', 'Value': gw['NatGatewayId']}],
                    StartTime=start, EndTime=end, Period=86400, Statistics=['Sum']
                )
                total = sum(dp['Sum'] for dp in metrics['Datapoints']) if metrics['Datapoints'] else 0
                if total == 0:
                    findings.append(Finding(
                        check_id="aws-nat-001", service="NAT",
                        resource_id=gw['NatGatewayId'], region=region, account_id=account_id,
                        issue=f"NAT Gateway unused ({days} days, 0 bytes)",
                        severity=Severity.HIGH, finding_type=FindingType.COST,
                        risk="Waste $32.85/mo per idle NAT Gateway",
                        monthly_savings=32.85,
                    ))
            except Exception:
                continue
    except Exception:
        pass

    return findings
