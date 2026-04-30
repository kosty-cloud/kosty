from datetime import datetime, timedelta, timezone
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-lambda-001", service="Lambda", provider="aws", finding_type=FindingType.COST, description="Find Lambda functions with 0 invocations")
def check_unused_functions(session, region, days=30, **kwargs):
    """Flag functions generating no traffic."""
    lam = session.client('lambda', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        for func in lam.list_functions()['Functions']:
            try:
                metrics = cw.get_metric_statistics(
                    Namespace='AWS/Lambda', MetricName='Invocations',
                    Dimensions=[{'Name': 'FunctionName', 'Value': func['FunctionName']}],
                    StartTime=start, EndTime=end, Period=86400, Statistics=['Sum']
                )
                if not metrics['Datapoints'] or sum(dp['Sum'] for dp in metrics['Datapoints']) == 0:
                    findings.append(Finding(
                        check_id="aws-lambda-001", service="Lambda",
                        resource_id=func['FunctionName'], region=region, account_id=account_id,
                        issue=f"0 invocations in {days} days",
                        severity=Severity.LOW, finding_type=FindingType.COST,
                        risk="Dead code — potential security surface with no business value",
                        arn=func['FunctionArn'],
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-lambda-002", service="Lambda", provider="aws", finding_type=FindingType.SECURITY, description="Find publicly accessible Lambda functions")
def check_public_functions(session, region, **kwargs):
    """Flag functions with resource policies allowing wildcard principals."""
    lam = session.client('lambda', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for func in lam.list_functions()['Functions']:
            try:
                policy = lam.get_policy(FunctionName=func['FunctionName']).get('Policy', '{}')
                if '"*"' in policy:
                    findings.append(Finding(
                        check_id="aws-lambda-002", service="Lambda",
                        resource_id=func['FunctionName'], region=region, account_id=account_id,
                        issue="Publicly accessible function",
                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                        risk="Anyone can invoke this function",
                        arn=func['FunctionArn'],
                    ))
            except lam.exceptions.ResourceNotFoundException:
                continue
            except Exception:
                continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-lambda-003", service="Lambda", provider="aws", finding_type=FindingType.SECURITY, description="Find functions using outdated runtimes")
def check_outdated_runtime(session, region, **kwargs):
    """Flag functions on EOL runtimes missing security patches."""
    lam = session.client('lambda', region_name=region)
    account_id = get_account_id(session)
    findings = []
    outdated = ['python2.7', 'python3.6', 'python3.7', 'nodejs8.10', 'nodejs10.x', 'nodejs12.x', 'dotnetcore2.1', 'dotnetcore3.1', 'go1.x', 'ruby2.5', 'ruby2.7']
    try:
        for func in lam.list_functions()['Functions']:
            if func.get('Runtime', '') in outdated:
                findings.append(Finding(
                    check_id="aws-lambda-003", service="Lambda",
                    resource_id=func['FunctionName'], region=region, account_id=account_id,
                    issue=f"Outdated runtime: {func['Runtime']}",
                    severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                    risk="EOL runtime — no security patches",
                    arn=func['FunctionArn'],
                ))
    except Exception:
        pass
    return findings
