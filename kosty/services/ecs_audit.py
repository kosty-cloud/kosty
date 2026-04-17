import boto3
from typing import List, Dict, Any


class ECSAuditService:
    def __init__(self):
        self.cost_checks = []
        self.security_checks = ['find_privileged_tasks']

    def find_privileged_tasks(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find ECS task definitions with privileged containers"""
        ecs = session.client('ecs', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            paginator = ecs.get_paginator('list_task_definition_families')
            for page in paginator.paginate(status='ACTIVE'):
                for family in page['families']:
                    try:
                        td = ecs.describe_task_definition(taskDefinition=family)['taskDefinition']

                        for container in td.get('containerDefinitions', []):
                            if container.get('privileged', False):
                                results.append({
                                    'AccountId': account_id, 'Region': region, 'Service': 'ECS',
                                    'ResourceId': f"{family}:{container['name']}",
                                    'ResourceName': f"{family}:{container['name']}",
                                    'ARN': td.get('taskDefinitionArn', ''),
                                    'Issue': f'Container "{container["name"]}" runs in privileged mode',
                                    'type': 'security',
                                    'Risk': 'Full host access — container escape leads to node compromise',
                                    'severity': 'critical', 'check': 'privileged_tasks'
                                })
                    except Exception:
                        continue
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking ECS privileged tasks: {e}")

        return results

    def cost_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return []

    def security_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        results = []
        for check in self.security_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results

    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.security_audit(session, region, config_manager=config_manager, **kwargs)

    def check_privileged_tasks(self, session, region, **kwargs):
        return self.find_privileged_tasks(session, region, **kwargs)
