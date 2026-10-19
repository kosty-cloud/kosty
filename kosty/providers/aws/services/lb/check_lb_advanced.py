from datetime import datetime, timedelta, timezone
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-lb-003", service="LB", provider="aws", finding_type=FindingType.COST, description="Find underutilized load balancers")
def check_underutilized_lbs(session: 'boto3.Session', region: str, days=7, **kwargs) -> List[Finding]:
    """Flag ALBs with very low request count — possibly unnecessary."""
    elb = session.client('elbv2', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        for lb in elb.describe_load_balancers()['LoadBalancers']:
            try:
                # Extract ALB dimension from ARN
                arn_suffix = '/'.join(lb['LoadBalancerArn'].split(':loadbalancer/')[1:])
                metrics = cw.get_metric_statistics(
                    Namespace='AWS/ApplicationELB', MetricName='RequestCount',
                    Dimensions=[{'Name': 'LoadBalancer', 'Value': arn_suffix}],
                    StartTime=start, EndTime=end, Period=86400, Statistics=['Sum']
                )
                total = sum(dp['Sum'] for dp in metrics['Datapoints']) if metrics['Datapoints'] else 0
                if total < 100:
                    findings.append(Finding(
                        check_id="aws-lb-003", service="LB",
                        resource_id=lb['LoadBalancerName'], region=region, account_id=account_id,
                        issue=f"Underutilized ({int(total)} requests in {days} days)",
                        severity=Severity.MEDIUM, finding_type=FindingType.COST,
                        risk="$16.43/mo for near-zero traffic",
                        arn=lb['LoadBalancerArn'], monthly_savings=16.43,
                    ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings


@register_check(check_id="aws-lb-004", service="LB", provider="aws", finding_type=FindingType.SECURITY, description="Find ALBs using deprecated TLS versions")
def check_deprecated_tls(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag listeners accepting TLS 1.0 or 1.1 connections."""
    elb = session.client('elbv2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    deprecated_policies = ['ELBSecurityPolicy-2016-08', 'ELBSecurityPolicy-TLS-1-0-2015-04', 'ELBSecurityPolicy-TLS-1-1-2017-01']
    try:
        for lb in elb.describe_load_balancers()['LoadBalancers']:
            try:
                listeners = elb.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
                for listener in listeners['Listeners']:
                    policy = listener.get('SslPolicy', '')
                    if policy in deprecated_policies:
                        findings.append(Finding(
                            check_id="aws-lb-004", service="LB",
                            resource_id=lb['LoadBalancerName'], region=region, account_id=account_id,
                            issue=f"Deprecated TLS policy: {policy}",
                            severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                            risk="TLS 1.0/1.1 vulnerable to POODLE and BEAST attacks",
                            arn=lb['LoadBalancerArn'],
                        ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings


@register_check(check_id="aws-lb-005", service="LB", provider="aws", finding_type=FindingType.SECURITY, description="Find ALBs without access logs enabled")
def check_no_access_logs(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag load balancers with no access logging — blind to abuse patterns."""
    elb = session.client('elbv2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for lb in elb.describe_load_balancers()['LoadBalancers']:
            try:
                attrs = elb.describe_load_balancer_attributes(LoadBalancerArn=lb['LoadBalancerArn'])
                access_logs = next((a for a in attrs['Attributes'] if a['Key'] == 'access_logs.s3.enabled'), None)
                if not access_logs or access_logs['Value'] != 'true':
                    findings.append(Finding(
                        check_id="aws-lb-005", service="LB",
                        resource_id=lb['LoadBalancerName'], region=region, account_id=account_id,
                        issue="Access logs not enabled",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="No visibility into request patterns for forensics",
                        arn=lb['LoadBalancerArn'],
                    ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings


@register_check(check_id="aws-lb-006", service="LB", provider="aws", finding_type=FindingType.COST, description="Find Classic Load Balancers (should migrate to ALB/NLB)")
def check_classic_lbs(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag CLBs — deprecated, more expensive, fewer features than ALB/NLB."""
    elb_classic = session.client('elb', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for lb in elb_classic.describe_load_balancers().get('LoadBalancerDescriptions', []):
            findings.append(Finding(
                check_id="aws-lb-006", service="LB",
                resource_id=lb['LoadBalancerName'], region=region, account_id=account_id,
                issue="Classic Load Balancer — migrate to ALB or NLB",
                severity=Severity.MEDIUM, finding_type=FindingType.COST,
                risk="CLBs lack modern features and cost more per connection",
            ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
