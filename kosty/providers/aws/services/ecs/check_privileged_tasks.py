from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(
    check_id="aws-ecs-001",
    service="ECS",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find task definitions with privileged containers",
)
def check_privileged_tasks(session, region, **kwargs):
    """Flag containers running in privileged mode — container escape risk."""
    ecs = session.client('ecs', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        paginator = ecs.get_paginator('list_task_definition_families')
        for page in paginator.paginate(status='ACTIVE'):
            for family in page['families']:
                try:
                    td = ecs.describe_task_definition(taskDefinition=family)['taskDefinition']
                    for container in td.get('containerDefinitions', []):
                        if container.get('privileged', False):
                            findings.append(Finding(
                                check_id="aws-ecs-001", service="ECS",
                                resource_id=f"{family}:{container['name']}",
                                region=region, account_id=account_id,
                                issue=f'Container "{container["name"]}" runs in privileged mode',
                                severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                                risk="Full host access — container escape leads to node compromise",
                                arn=td.get('taskDefinitionArn', ''),
                            ))
                except Exception:
                    continue
    except Exception:
        pass

    return findings
