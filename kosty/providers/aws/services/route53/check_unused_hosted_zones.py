from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-route53-001",
    service="Route53",
    provider="aws",
    finding_type=FindingType.COST,
    description="Find hosted zones with no record sets beyond NS/SOA",
)
def check_unused_hosted_zones(session, region, **kwargs):
    """Flag hosted zones that contain only the default NS and SOA records."""
    route53 = session.client('route53')
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        zones = route53.list_hosted_zones().get('HostedZones', [])
        for zone in zones:
            try:
                records = route53.list_resource_record_sets(
                    HostedZoneId=zone['Id'], MaxItems='10'
                )
                non_default = [r for r in records['ResourceRecordSets'] if r['Type'] not in ['NS', 'SOA']]
                if not non_default:
                    findings.append(Finding(
                        check_id="aws-route53-001", service="Route53",
                        resource_id=zone['Name'].rstrip('.'), region='global', account_id=account_id,
                        issue=f"Hosted zone with no custom records",
                        severity=Severity.LOW, finding_type=FindingType.COST,
                        risk="$0.50/mo per unused hosted zone",
                        monthly_savings=0.50,
                    ))
            except Exception:
                continue
    except Exception:
        pass

    return findings
