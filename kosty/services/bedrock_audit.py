import boto3
from typing import List, Dict, Any


class BedrockAuditService:
    def __init__(self):
        self.cost_checks = ['find_no_budget_limits']
        self.security_checks = ['find_no_logging']

    def find_no_logging(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if Bedrock model invocation logging is enabled"""
        bedrock = session.client('bedrock', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            config = bedrock.get_model_invocation_logging_configuration()
            logging_config = config.get('loggingConfig', {})

            has_s3 = bool(logging_config.get('s3Config', {}).get('bucketName'))
            has_cw = bool(logging_config.get('cloudWatchConfig', {}).get('logGroupName'))

            if not has_s3 and not has_cw:
                results.append({
                    'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                    'ResourceId': 'bedrock-logging', 'ResourceName': 'Bedrock Logging',
                    'Issue': 'Bedrock model invocation logging not enabled',
                    'type': 'security', 'Risk': 'No audit trail on GenAI usage — prompt injection and data leakage go undetected',
                    'severity': 'high', 'check': 'no_logging'
                })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking Bedrock logging: {e}")

        return results

    def find_no_budget_limits(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if AWS Budgets exist for Bedrock spend"""
        budgets = session.client('budgets', region_name='us-east-1')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        try:
            resp = budgets.describe_budgets(AccountId=account_id)
            budget_list = resp.get('Budgets', [])

            has_bedrock_budget = any(
                'bedrock' in b.get('BudgetName', '').lower() or
                any('bedrock' in str(f).lower() for f in b.get('CostFilters', {}).values())
                for b in budget_list
            )

            if not has_bedrock_budget:
                results.append({
                    'AccountId': account_id, 'Region': region, 'Service': 'Bedrock',
                    'ResourceId': 'bedrock-budget', 'ResourceName': 'Bedrock Budget',
                    'Issue': 'No AWS Budget configured for Bedrock spend',
                    'type': 'cost', 'Risk': 'Stolen API key or runaway automation = unlimited GenAI spend with no alert',
                    'severity': 'high', 'check': 'no_budget_limits'
                })
        except Exception as e:
            if 'AccessDeniedException' not in str(e):
                print(f"Error checking Bedrock budgets: {e}")

        return results

    def cost_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        results = []
        for check in self.cost_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results

    def security_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        results = []
        for check in self.security_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results

    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        results = []
        results.extend(self.cost_audit(session, region, config_manager=config_manager, **kwargs))
        results.extend(self.security_audit(session, region, config_manager=config_manager, **kwargs))
        return results

    def check_no_logging(self, session, region, **kwargs):
        return self.find_no_logging(session, region, **kwargs)

    def check_no_budget_limits(self, session, region, **kwargs):
        return self.find_no_budget_limits(session, region, **kwargs)
