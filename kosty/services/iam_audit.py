import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any
from datetime import datetime, timedelta
import json

class IAMAuditService:
    def __init__(self):
        self.cost_checks = ['find_unused_roles']
        self.security_checks = ['find_root_access_keys', 'find_old_access_keys', 'find_inactive_users', 
                               'find_wildcard_policies', 'find_admin_no_mfa', 'find_weak_password_policy',
                               'find_no_password_rotation', 'find_cross_account_no_external_id']
    
    # Cost Audit Methods
    def find_unused_roles(self, session: boto3.Session, region: str, days: int = 90, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find unused roles creating resources"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        unused_roles = []
        
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            roles = iam.list_roles()
            
            for role in roles['Roles']:
                role_name = role['RoleName']
                
                # Skip AWS service roles
                if role_name.startswith('aws-') or role_name.startswith('AWSServiceRole'):
                    continue
                
                try:
                    # Get role last activity
                    role_details = iam.get_role(RoleName=role_name)
                    last_used = role_details['Role'].get('RoleLastUsed', {}).get('LastUsedDate')
                    
                    is_unused = False
                    if not last_used:
                        # Never used
                        is_unused = True
                    elif last_used.replace(tzinfo=None) < cutoff_date:
                        # Not used recently
                        is_unused = True
                    
                    if is_unused:
                        unused_roles.append({
                            'AccountId': account_id,
                            'Region': region,
                            'Service': 'IAM',
                            'ResourceId': role_name,
                            'ResourceName': role_name,
                            'Issue': 'Unused role creating resources',
                            'type': 'cost',
                            'Risk': 'HIGH',
                            'severity': 'high',
                            'Description': f"IAM role {role_name} unused for {days}+ days",
                            'ARN': role['Arn'],
                            'Details': {
                                'RoleName': role_name,
                                'RoleId': role['RoleId'],
                                'CreateDate': role['CreateDate'].isoformat(),
                                'LastUsed': last_used.isoformat() if last_used else 'Never'
                            }
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking unused roles: {e}")
        
        return unused_roles
    
    # Security Audit Methods
    def find_root_access_keys(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find root account has access keys"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        root_keys = []
        
        try:
            # Get account summary to check for root access keys
            summary = iam.get_account_summary()
            root_access_keys = summary['SummaryMap'].get('AccountAccessKeysPresent', 0)
            
            if root_access_keys > 0:
                root_keys.append({
                    'AccountId': account_id,
                    'Region': region,
                    'Service': 'IAM',
                    'ResourceId': 'root',
                    'ResourceName': 'root',
                    'Issue': 'Root account has access keys',
                    'type': 'security',
                    'Risk': 'CRITICAL',
                    'severity': 'critical',
                    'Description': 'Root account has active access keys - immediate security risk',
                    'ARN': f'arn:aws:iam::{account_id}:root',
                    'Details': {
                        'AccessKeysCount': root_access_keys
                    }
                })
        except Exception as e:
            print(f"Error checking root access keys: {e}")
        
        return root_keys
    
    def find_old_access_keys(self, session: boto3.Session, region: str, days: int = 90, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find access keys older than 90 days"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        old_keys = []
        
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            users = iam.list_users()
            
            for user in users['Users']:
                user_name = user['UserName']
                
                try:
                    access_keys = iam.list_access_keys(UserName=user_name)
                    
                    for key in access_keys['AccessKeyMetadata']:
                        key_age = (datetime.now() - key['CreateDate'].replace(tzinfo=None)).days
                        
                        if key_age > days:
                            old_keys.append({
                                'AccountId': account_id,
                                'Region': region,
                                'Service': 'IAM',
                                'ResourceId': user_name,
                                'ResourceName': user_name,
                                'Issue': f'Access keys older than {days} days',
                                'type': 'security',
                                'Risk': 'CRITICAL',
                                'severity': 'critical',
                                'Description': f"User {user_name} has access key aged {key_age} days",
                                'ARN': user['Arn'],
                                'Details': {
                                    'UserName': user_name,
                                    'AccessKeyId': key['AccessKeyId'],
                                    'CreateDate': key['CreateDate'].isoformat(),
                                    'Age': key_age,
                                    'Status': key['Status']
                                }
                            })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking old access keys: {e}")
        
        return old_keys
    
    def find_inactive_users(self, session: boto3.Session, region: str, days: int = 90, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find users inactive >90 days with active keys"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        inactive_users = []
        
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            users = iam.list_users()
            
            for user in users['Users']:
                user_name = user['UserName']
                
                try:
                    # Check if user has active access keys
                    access_keys = iam.list_access_keys(UserName=user_name)
                    has_active_keys = any(key['Status'] == 'Active' for key in access_keys['AccessKeyMetadata'])
                    
                    if not has_active_keys:
                        continue
                    
                    # Get user last activity
                    user_details = iam.get_user(UserName=user_name)
                    password_last_used = user_details['User'].get('PasswordLastUsed')
                    
                    # Check access key last used
                    last_activity = None
                    for key in access_keys['AccessKeyMetadata']:
                        try:
                            key_last_used = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                            key_last_activity = key_last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                            if key_last_activity:
                                if not last_activity or key_last_activity > last_activity:
                                    last_activity = key_last_activity
                        except Exception:
                            continue
                    
                    # Compare with password last used
                    if password_last_used:
                        if not last_activity or password_last_used > last_activity:
                            last_activity = password_last_used
                    
                    # Check if inactive
                    is_inactive = False
                    if not last_activity:
                        is_inactive = True
                    elif last_activity.replace(tzinfo=None) < cutoff_date:
                        is_inactive = True
                    
                    if is_inactive:
                        inactive_users.append({
                            'AccountId': account_id,
                            'Region': region,
                            'Service': 'IAM',
                            'ResourceId': user_name,
                            'ResourceName': user_name,
                            'Issue': f'User inactive >{days} days with active keys',
                            'type': 'security',
                            'Risk': 'HIGH',
                            'severity': 'high',
                            'Description': f"User {user_name} inactive for {days}+ days but has active access keys",
                            'ARN': user['Arn'],
                            'Details': {
                                'UserName': user_name,
                                'CreateDate': user['CreateDate'].isoformat(),
                                'LastActivity': last_activity.isoformat() if last_activity else 'Never',
                                'ActiveKeys': len([k for k in access_keys['AccessKeyMetadata'] if k['Status'] == 'Active'])
                            }
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking inactive users: {e}")
        
        return inactive_users
    
    def find_wildcard_policies(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find policies using Action:* or Resource:*"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        wildcard_policies = []
        
        try:
            # Check user policies
            users = iam.list_users()
            for user in users['Users']:
                user_name = user['UserName']
                
                try:
                    # Check inline policies
                    inline_policies = iam.list_user_policies(UserName=user_name)
                    for policy_name in inline_policies['PolicyNames']:
                        policy = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                        if self._has_wildcard_permissions(policy['PolicyDocument']):
                            wildcard_policies.append({
                                'AccountId': account_id,
                                'Type': 'User',
                                'Name': user_name,
                                'PolicyName': policy_name,
                                'PolicyType': 'Inline',
                                'ARN': user['Arn'],
                                'Region': region,
                                'Issue': 'Policy uses Action:* or Resource:*',
                                'type': 'security',
                                'Risk': 'Privilege escalation risk',
                                'severity': 'high',
                                'Service': 'IAM'
                            })
                    
                    # Check attached policies
                    attached_policies = iam.list_attached_user_policies(UserName=user_name)
                    for policy in attached_policies['AttachedPolicies']:
                        if policy['PolicyArn'].startswith('arn:aws:iam::aws:'):
                            continue  # Skip AWS managed policies
                        
                        try:
                            policy_version = iam.get_policy(PolicyArn=policy['PolicyArn'])
                            policy_doc = iam.get_policy_version(
                                PolicyArn=policy['PolicyArn'],
                                VersionId=policy_version['Policy']['DefaultVersionId']
                            )
                            if self._has_wildcard_permissions(policy_doc['PolicyVersion']['Document']):
                                wildcard_policies.append({
                                    'AccountId': account_id,
                                    'Type': 'User',
                                    'Name': user_name,
                                    'PolicyName': policy['PolicyName'],
                                    'PolicyType': 'Managed',
                                    'ARN': user['Arn'],
                                    'Region': region,
                                    'Issue': 'Policy uses Action:* or Resource:*',
                                    'type': 'security',
                                    'Risk': 'Privilege escalation risk',
                                    'severity': 'high',
                                    'Service': 'IAM'
                                })
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking wildcard policies: {e}")
        
        return wildcard_policies
    
    def _has_wildcard_permissions(self, policy_document):
        """Check if policy document has wildcard permissions"""
        if isinstance(policy_document, str):
            policy_document = json.loads(policy_document)
        
        statements = policy_document.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
            
            actions = statement.get('Action', [])
            resources = statement.get('Resource', [])
            
            if not isinstance(actions, list):
                actions = [actions]
            if not isinstance(resources, list):
                resources = [resources]
            
            # Check for wildcard actions or resources
            if '*' in actions or '*' in resources:
                return True
        
        return False
    
    def find_admin_no_mfa(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find admin access without MFA"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        admin_no_mfa = []
        
        try:
            users = iam.list_users()
            
            for user in users['Users']:
                user_name = user['UserName']
                
                try:
                    # Check if user has admin permissions
                    has_admin = False
                    
                    # Check attached policies
                    attached_policies = iam.list_attached_user_policies(UserName=user_name)
                    for policy in attached_policies['AttachedPolicies']:
                        if 'Administrator' in policy['PolicyName'] or policy['PolicyArn'].endswith('AdministratorAccess'):
                            has_admin = True
                            break
                    
                    # Check groups
                    if not has_admin:
                        groups = iam.get_groups_for_user(UserName=user_name)
                        for group in groups['Groups']:
                            group_policies = iam.list_attached_group_policies(GroupName=group['GroupName'])
                            for policy in group_policies['AttachedPolicies']:
                                if 'Administrator' in policy['PolicyName'] or policy['PolicyArn'].endswith('AdministratorAccess'):
                                    has_admin = True
                                    break
                            if has_admin:
                                break
                    
                    if has_admin:
                        # Check if user has MFA
                        mfa_devices = iam.list_mfa_devices(UserName=user_name)
                        if not mfa_devices['MFADevices']:
                            admin_no_mfa.append({
                                'AccountId': account_id,
                                'UserName': user_name,
                                'ARN': user['Arn'],
                                'Region': region,
                                'CreateDate': user['CreateDate'].isoformat(),
                                'MFADevices': len(mfa_devices['MFADevices']),
                                'Issue': 'Admin access without MFA',
                                'type': 'security',
                                'Risk': 'Account takeover via phishing',
                                'severity': 'high',
                                'Service': 'IAM'
                            })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking admin without MFA: {e}")
        
        return admin_no_mfa
    
    def find_weak_password_policy(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find password policy allows weak passwords"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        weak_policy = []
        
        try:
            try:
                policy = iam.get_account_password_policy()['PasswordPolicy']
            except iam.exceptions.NoSuchEntityException:
                # No password policy exists
                weak_policy.append({
                    'AccountId': account_id,
                    'Region': region,
                    'Service': 'IAM',
                    'ResourceId': 'password-policy',
                    'ResourceName': 'Password Policy',
                    'Issue': 'Password policy allows weak passwords',
                    'type': 'security',
                    'Risk': 'MEDIUM',
                    'severity': 'medium',
                    'Description': 'No password policy configured - allows weak passwords',
                    'ARN': f'arn:aws:iam::{account_id}:account-password-policy',
                    'Details': {
                        'PolicyStatus': 'No password policy configured'
                    }
                })
                return weak_policy
            
            # Check for weak settings
            weak_settings = []
            
            if policy.get('MinimumPasswordLength', 0) < 8:
                weak_settings.append(f"Min length: {policy.get('MinimumPasswordLength', 0)} < 8")
            
            if not policy.get('RequireUppercaseCharacters', False):
                weak_settings.append("No uppercase required")
            
            if not policy.get('RequireLowercaseCharacters', False):
                weak_settings.append("No lowercase required")
            
            if not policy.get('RequireNumbers', False):
                weak_settings.append("No numbers required")
            
            if not policy.get('RequireSymbols', False):
                weak_settings.append("No symbols required")
            
            if weak_settings:
                weak_policy.append({
                    'AccountId': account_id,
                    'Region': region,
                    'Service': 'IAM',
                    'ResourceId': 'password-policy',
                    'ResourceName': 'Password Policy',
                    'Issue': 'Password policy allows weak passwords',
                    'type': 'security',
                    'Risk': 'MEDIUM',
                    'severity': 'medium',
                    'Description': f"Password policy has weak settings: {', '.join(weak_settings)}",
                    'ARN': f'arn:aws:iam::{account_id}:account-password-policy',
                    'Details': {
                        'WeakSettings': weak_settings
                    }
                })
        except Exception as e:
            print(f"Error checking password policy: {e}")
        
        return weak_policy
    
    def find_no_password_rotation(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find no password rotation policy"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        no_rotation = []
        
        try:
            try:
                policy = iam.get_account_password_policy()['PasswordPolicy']
                max_age = policy.get('MaxPasswordAge')
                
                if not max_age or max_age > 90:
                    no_rotation.append({
                        'AccountId': account_id,
                        'Region': region,
                        'Service': 'IAM',
                        'ResourceId': 'password-policy',
                        'ResourceName': 'Password Policy',
                        'Issue': 'No password rotation policy',
                        'type': 'security',
                        'Risk': 'MEDIUM',
                        'severity': 'medium',
                        'Description': f"Password rotation not enforced (max age: {max_age or 'Not set'})",
                        'ARN': f'arn:aws:iam::{account_id}:account-password-policy',
                        'Details': {
                            'MaxPasswordAge': max_age or 'Not set'
                        }
                    })
            except iam.exceptions.NoSuchEntityException:
                no_rotation.append({
                    'AccountId': account_id,
                    'Region': region,
                    'Service': 'IAM',
                    'ResourceId': 'password-policy',
                    'ResourceName': 'Password Policy',
                    'Issue': 'No password rotation policy',
                    'type': 'security',
                    'Risk': 'MEDIUM',
                    'severity': 'medium',
                    'Description': 'No password policy configured - no rotation enforced',
                    'ARN': f'arn:aws:iam::{account_id}:account-password-policy',
                    'Details': {
                        'MaxPasswordAge': 'No policy'
                    }
                })
        except Exception as e:
            print(f"Error checking password rotation: {e}")
        
        return no_rotation
    
    def find_cross_account_no_external_id(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find cross-account roles without ExternalId"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        no_external_id = []
        
        try:
            roles = iam.list_roles()
            
            for role in roles['Roles']:
                role_name = role['RoleName']
                
                try:
                    assume_role_policy = role['AssumeRolePolicyDocument']
                    if isinstance(assume_role_policy, str):
                        assume_role_policy = json.loads(assume_role_policy)
                    
                    statements = assume_role_policy.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements]
                    
                    for statement in statements:
                        principal = statement.get('Principal', {})
                        if isinstance(principal, dict) and 'AWS' in principal:
                            aws_principals = principal['AWS']
                            if not isinstance(aws_principals, list):
                                aws_principals = [aws_principals]
                            
                            # Check for cross-account principals
                            for aws_principal in aws_principals:
                                if ':' in aws_principal and account_id not in aws_principal:
                                    # This is a cross-account role
                                    condition = statement.get('Condition', {})
                                    has_external_id = any('ExternalId' in str(cond) for cond in condition.values()) if condition else False
                                    
                                    if not has_external_id:
                                        no_external_id.append({
                                            'AccountId': account_id,
                                            'RoleName': role_name,
                                            'ARN': role['Arn'],
                                            'Region': region,
                                            'CrossAccountPrincipal': aws_principal,
                                            'Issue': 'Cross-account role without ExternalId',
                                            'type': 'security',
                                            'Risk': 'Confused deputy attack',
                                            'severity': 'high',
                                            'Service': 'IAM'
                                        })
                                        break
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking cross-account roles: {e}")
        
        return no_external_id
    
    # Audit Methods
    def cost_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all cost-related audits"""
        results = []
        for check in self.cost_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def security_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all security-related audits"""
        results = []
        for check in self.security_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all audits (cost + security)"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        return results
    
    # Individual Check Method Aliases
    def check_unused_roles(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_unused_roles(session, region, **kwargs)
    
    def check_root_access_keys(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_root_access_keys(session, region, **kwargs)
    
    def check_old_access_keys(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_old_access_keys(session, region, **kwargs)
    
    def check_inactive_users(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_inactive_users(session, region, **kwargs)
    
    def check_wildcard_policies(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_wildcard_policies(session, region, **kwargs)
    
    def check_admin_no_mfa(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_admin_no_mfa(session, region, **kwargs)
    
    def check_weak_password_policy(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_weak_password_policy(session, region, **kwargs)
    
    def check_no_password_rotation(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_no_password_rotation(session, region, **kwargs)
    
    def check_cross_account_no_external_id(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_cross_account_no_external_id(session, region, **kwargs)