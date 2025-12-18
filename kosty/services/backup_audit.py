import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any

class BackupAuditService:
    def __init__(self):
        self.service_name = "Backup"
        self.cost_checks = ['check_empty_backup_vaults', 'check_cross_region_backup_dev_test']
        self.security_checks = []

    def cost_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all cost-related AWS Backup audits"""
        results = []
        for check in self.cost_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def security_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all security-related AWS Backup audits"""
        return []

    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all AWS Backup audits"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        return results

    def check_empty_backup_vaults(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find empty backup vaults"""
        backup = session.client('backup', region_name=region)
        results = []
        
        try:
            # Get all backup vaults
            vaults_response = backup.list_backup_vaults()
            
            for vault in vaults_response['BackupVaultList']:
                vault_name = vault['BackupVaultName']
                
                # Skip default vault
                if vault_name == 'default':
                    continue
                
                try:
                    # Check if vault has any recovery points
                    recovery_points_response = backup.list_recovery_points_by_backup_vault(
                        BackupVaultName=vault_name,
                        MaxResults=1
                    )
                    
                    if not recovery_points_response['RecoveryPoints']:
                        results.append({
                            'AccountId': session.client('sts').get_caller_identity()['Account'],
                            'Region': region,
                            'Service': self.service_name,
                            'ResourceId': vault_name,
                            'ResourceName': vault_name,
                            'ResourceArn': vault['BackupVaultArn'],
                            'Issue': 'Empty backup vault',
                            'type': 'cost',
                            'Risk': 'Waste $0.10/mo per vault',
                            'severity': 'low',
                            'Details': {
                                'BackupVaultName': vault_name,
                                'CreationDate': vault.get('CreationDate').isoformat() if vault.get('CreationDate') else None,
                                'NumberOfRecoveryPoints': vault.get('NumberOfRecoveryPoints', 0)
                            }
                        })
                except Exception:
                    continue
        except Exception as e:
            pass
        
        return results

    def check_cross_region_backup_dev_test(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find cross-region backup for dev/test environments"""
        backup = session.client('backup', region_name=region)
        results = []
        
        try:
            # Get all backup plans
            plans_response = backup.list_backup_plans()
            
            for plan in plans_response['BackupPlansList']:
                plan_id = plan['BackupPlanId']
                
                try:
                    # Get backup plan details
                    plan_details = backup.get_backup_plan(BackupPlanId=plan_id)
                    plan_name = plan_details['BackupPlan']['BackupPlanName'].lower()
                    
                    # Check if this looks like a dev/test environment
                    dev_test_indicators = ['qua','dev', 'test', 'staging', 'qa', 'development']
                    is_dev_test = any(indicator in plan_name for indicator in dev_test_indicators)
                    
                    if is_dev_test:
                        # Check for cross-region copy rules
                        for rule in plan_details['BackupPlan']['Rules']:
                            copy_actions = rule.get('CopyActions', [])
                            
                            for copy_action in copy_actions:
                                destination_vault_arn = copy_action.get('DestinationBackupVaultArn', '')
                                
                                # Check if destination is in different region
                                if region not in destination_vault_arn:
                                    results.append({
                                        'AccountId': session.client('sts').get_caller_identity()['Account'],
                                        'Region': region,
                                        'Service': self.service_name,
                                        'ResourceId': plan_id,
                                        'ResourceName': plan_details['BackupPlan']['BackupPlanName'],
                                        'ResourceArn': plan_details['BackupPlanArn'],
                                        'Issue': 'Cross-region backup for dev/test',
                                        'type': 'cost',
                                        'Risk': 'Waste 2x storage + transfer',
                                        'severity': 'medium',
                                        'Details': {
                                            'BackupPlanName': plan_details['BackupPlan']['BackupPlanName'],
                                            'BackupPlanId': plan_id,
                                            'RuleName': rule.get('RuleName'),
                                            'DestinationVaultArn': destination_vault_arn
                                        }
                                    })
                                    break
                except Exception:
                    continue
        except Exception as e:
            pass
        
        return results

