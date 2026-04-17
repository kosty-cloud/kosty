import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any
from datetime import datetime, timedelta
import json

class IAMAuditService:
    def __init__(self):
        self.cost_checks = []
        self.security_checks = ['find_unused_roles', 'find_root_access_keys', 'find_old_access_keys', 'find_inactive_users', 
                               'find_wildcard_policies', 'find_admin_no_mfa', 'find_weak_password_policy',
                               'find_no_password_rotation', 'find_cross_account_no_external_id',
                               'find_all_users_mfa', 'find_root_mfa', 'find_unused_access_keys',
                               'find_inline_policies', 'find_passrole_permissions', 'find_shared_lambda_roles',
                               'find_multiple_active_keys', 'find_wildcard_assume_role',
                               'find_privilege_escalation']
    
    # Cost Audit Methods
    def find_unused_roles(self, session: boto3.Session, region: str, days: int = 30, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find unused roles — flags admin roles as critical"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        unused_roles = []
        
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            roles = iam.list_roles()
            
            for role in roles['Roles']:
                role_name = role['RoleName']
                
                if role_name.startswith('aws-') or role_name.startswith('AWSServiceRole'):
                    continue
                
                try:
                    role_details = iam.get_role(RoleName=role_name)['Role']
                    last_used = role_details.get('RoleLastUsed', {}).get('LastUsedDate')
                    
                    is_unused = not last_used or last_used.replace(tzinfo=None) < cutoff_date
                    if not is_unused:
                        continue
                    
                    has_admin = self._role_has_admin(iam, role_name)
                    severity = 'critical' if has_admin else 'high'
                    issue = f'Unused admin role ({days}+ days)' if has_admin else f'Unused role ({days}+ days)'
                    risk = 'Dormant admin role — prime target for privilege escalation' if has_admin else f'Stale role unused for {days}+ days'
                    
                    unused_roles.append({
                        'AccountId': account_id,
                        'Region': region,
                        'Service': 'IAM',
                        'ResourceId': role_name,
                        'ResourceName': role_name,
                        'Issue': issue,
                        'type': 'security',
                        'Risk': risk,
                        'severity': severity,
                        'ARN': role['Arn'],
                        'check': 'unused_roles',
                        'Details': {
                            'RoleName': role_name,
                            'RoleId': role['RoleId'],
                            'CreateDate': role['CreateDate'].isoformat(),
                            'LastUsed': last_used.isoformat() if last_used else 'Never',
                            'HasAdminAccess': has_admin
                        }
                    })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking unused roles: {e}")
        
        return unused_roles
    
    def _role_has_admin(self, iam, role_name: str) -> bool:
        """Check if a role has AdministratorAccess or Action:*/Resource:*"""
        try:
            for p in iam.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', []):
                if p['PolicyArn'].endswith('/AdministratorAccess'):
                    return True
            for pname in iam.list_role_policies(RoleName=role_name).get('PolicyNames', []):
                doc = iam.get_role_policy(RoleName=role_name, PolicyName=pname)['PolicyDocument']
                if self._has_wildcard_permissions(doc):
                    return True
        except Exception:
            pass
        return False
    
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
    
    def find_all_users_mfa(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find IAM users without MFA enabled"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            users = iam.list_users()
            for user in users['Users']:
                try:
                    mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])
                    # Only flag users with console access (password)
                    try:
                        iam.get_login_profile(UserName=user['UserName'])
                        has_console = True
                    except iam.exceptions.NoSuchEntityException:
                        has_console = False
                    
                    if has_console and not mfa_devices['MFADevices']:
                        results.append({
                            'AccountId': account_id,
                            'Region': region,
                            'Service': 'IAM',
                            'ResourceId': user['UserName'],
                            'ResourceName': user['UserName'],
                            'ARN': user['Arn'],
                            'Issue': 'Console user without MFA enabled',
                            'type': 'security',
                            'Risk': 'Account compromise via credential theft',
                            'severity': 'high',
                            'check': 'all_users_mfa'
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking users MFA: {e}")
        
        return results
    
    def find_root_mfa(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if MFA is enabled for the root account"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            summary = iam.get_account_summary()
            root_mfa = summary['SummaryMap'].get('AccountMFAEnabled', 0)
            
            if root_mfa == 0:
                results.append({
                    'AccountId': account_id,
                    'Region': region,
                    'Service': 'IAM',
                    'ResourceId': 'root',
                    'ResourceName': 'root',
                    'ARN': f'arn:aws:iam::{account_id}:root',
                    'Issue': 'Root account does not have MFA enabled',
                    'type': 'security',
                    'Risk': 'Full account takeover if root credentials are compromised',
                    'severity': 'critical',
                    'check': 'root_mfa'
                })
        except Exception as e:
            print(f"Error checking root MFA: {e}")
        
        return results
    
    def find_unused_access_keys(self, session: boto3.Session, region: str, days: int = 90, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find active access keys unused for 90+ days"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            users = iam.list_users()
            cutoff_date = datetime.now() - timedelta(days=days)
            
            for user in users['Users']:
                try:
                    access_keys = iam.list_access_keys(UserName=user['UserName'])
                    for key in access_keys['AccessKeyMetadata']:
                        if key['Status'] != 'Active':
                            continue
                        key_last_used = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                        last_used_date = key_last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                        
                        is_unused = False
                        if not last_used_date:
                            is_unused = True
                        elif last_used_date.replace(tzinfo=None) < cutoff_date:
                            is_unused = True
                        
                        if is_unused:
                            results.append({
                                'AccountId': account_id,
                                'Region': region,
                                'Service': 'IAM',
                                'ResourceId': user['UserName'],
                                'ResourceName': user['UserName'],
                                'ARN': user['Arn'],
                                'Issue': f'Active access key unused for {days}+ days',
                                'type': 'security',
                                'Risk': 'Dormant credentials increase attack surface',
                                'severity': 'high',
                                'check': 'unused_access_keys',
                                'Details': {
                                    'AccessKeyId': key['AccessKeyId'],
                                    'LastUsed': last_used_date.isoformat() if last_used_date else 'Never',
                                    'Status': key['Status']
                                }
                            })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking unused access keys: {e}")
        
        return results
    
    def find_inline_policies(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Detect inline policies on users, groups, and roles"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            # Check users
            for user in iam.list_users()['Users']:
                try:
                    policies = iam.list_user_policies(UserName=user['UserName'])
                    for policy_name in policies['PolicyNames']:
                        results.append({
                            'AccountId': account_id,
                            'Region': region,
                            'Service': 'IAM',
                            'ResourceId': user['UserName'],
                            'ResourceName': user['UserName'],
                            'ARN': user['Arn'],
                            'Issue': f'Inline policy "{policy_name}" on user (use managed policies)',
                            'type': 'security',
                            'Risk': 'Inline policies are harder to audit and reuse',
                            'severity': 'medium',
                            'check': 'inline_policies'
                        })
                except Exception:
                    continue
            
            # Check roles
            for role in iam.list_roles()['Roles']:
                if role['RoleName'].startswith('aws-') or role['RoleName'].startswith('AWSServiceRole'):
                    continue
                try:
                    policies = iam.list_role_policies(RoleName=role['RoleName'])
                    for policy_name in policies['PolicyNames']:
                        results.append({
                            'AccountId': account_id,
                            'Region': region,
                            'Service': 'IAM',
                            'ResourceId': role['RoleName'],
                            'ResourceName': role['RoleName'],
                            'ARN': role['Arn'],
                            'Issue': f'Inline policy "{policy_name}" on role (use managed policies)',
                            'type': 'security',
                            'Risk': 'Inline policies are harder to audit and reuse',
                            'severity': 'medium',
                            'check': 'inline_policies'
                        })
                except Exception:
                    continue
            
            # Check groups
            for group in iam.list_groups()['Groups']:
                try:
                    policies = iam.list_group_policies(GroupName=group['GroupName'])
                    for policy_name in policies['PolicyNames']:
                        results.append({
                            'AccountId': account_id,
                            'Region': region,
                            'Service': 'IAM',
                            'ResourceId': group['GroupName'],
                            'ResourceName': group['GroupName'],
                            'ARN': group['Arn'],
                            'Issue': f'Inline policy "{policy_name}" on group (use managed policies)',
                            'type': 'security',
                            'Risk': 'Inline policies are harder to audit and reuse',
                            'severity': 'medium',
                            'check': 'inline_policies'
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking inline policies: {e}")
        
        return results
    
    def find_passrole_permissions(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Flag policies granting iam:PassRole with wildcard resource"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            paginator = iam.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):
                for policy in page['Policies']:
                    try:
                        version = iam.get_policy_version(
                            PolicyArn=policy['Arn'],
                            VersionId=policy['DefaultVersionId']
                        )
                        doc = version['PolicyVersion']['Document']
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        
                        statements = doc.get('Statement', [])
                        if not isinstance(statements, list):
                            statements = [statements]
                        
                        for stmt in statements:
                            if stmt.get('Effect') != 'Allow':
                                continue
                            actions = stmt.get('Action', [])
                            if not isinstance(actions, list):
                                actions = [actions]
                            resources = stmt.get('Resource', [])
                            if not isinstance(resources, list):
                                resources = [resources]
                            
                            has_passrole = any(a.lower() in ['iam:passrole', 'iam:*', '*'] for a in actions)
                            has_wildcard_resource = '*' in resources
                            
                            if has_passrole and has_wildcard_resource:
                                results.append({
                                    'AccountId': account_id,
                                    'Region': region,
                                    'Service': 'IAM',
                                    'ResourceId': policy['PolicyName'],
                                    'ResourceName': policy['PolicyName'],
                                    'ARN': policy['Arn'],
                                    'Issue': 'iam:PassRole with wildcard resource - privilege escalation risk',
                                    'type': 'security',
                                    'Risk': 'Attacker can escalate privileges by passing any role to any service',
                                    'severity': 'critical',
                                    'check': 'passrole_permissions'
                                })
                                break
                    except Exception:
                        continue
        except Exception as e:
            print(f"Error checking PassRole permissions: {e}")
        
        return results
    
    def find_shared_lambda_roles(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find Lambda functions sharing the same execution role"""
        lambda_client = session.client('lambda', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            role_map = {}  # role_arn -> [function_names]
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for func in page['Functions']:
                    role_arn = func.get('Role', '')
                    role_map.setdefault(role_arn, []).append(func['FunctionName'])
            
            for role_arn, functions in role_map.items():
                if len(functions) > 1:
                    for func_name in functions:
                        results.append({
                            'AccountId': account_id,
                            'Region': region,
                            'Service': 'IAM',
                            'ResourceId': func_name,
                            'ResourceName': func_name,
                            'ARN': role_arn,
                            'Issue': f'Lambda shares execution role with {len(functions)-1} other function(s)',
                            'type': 'security',
                            'Risk': 'Blast radius expansion - compromise of one function affects all',
                            'severity': 'medium',
                            'check': 'shared_lambda_roles',
                            'Details': {
                                'SharedRole': role_arn,
                                'SharedWith': [f for f in functions if f != func_name]
                            }
                        })
        except Exception as e:
            print(f"Error checking shared Lambda roles: {e}")
        
        return results
    
    def find_multiple_active_keys(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find users with more than one active access key"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            for user in iam.list_users()['Users']:
                try:
                    keys = iam.list_access_keys(UserName=user['UserName'])
                    active_keys = [k for k in keys['AccessKeyMetadata'] if k['Status'] == 'Active']
                    if len(active_keys) > 1:
                        results.append({
                            'AccountId': account_id,
                            'Region': region,
                            'Service': 'IAM',
                            'ResourceId': user['UserName'],
                            'ResourceName': user['UserName'],
                            'ARN': user['Arn'],
                            'Issue': f'User has {len(active_keys)} active access keys',
                            'type': 'security',
                            'Risk': 'Increased attack surface and harder key rotation',
                            'severity': 'medium',
                            'check': 'multiple_active_keys'
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking multiple active keys: {e}")
        
        return results
    
    def find_wildcard_assume_role(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Flag policies granting sts:AssumeRole with wildcard resource"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            paginator = iam.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):
                for policy in page['Policies']:
                    try:
                        version = iam.get_policy_version(
                            PolicyArn=policy['Arn'],
                            VersionId=policy['DefaultVersionId']
                        )
                        doc = version['PolicyVersion']['Document']
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        
                        statements = doc.get('Statement', [])
                        if not isinstance(statements, list):
                            statements = [statements]
                        
                        for stmt in statements:
                            if stmt.get('Effect') != 'Allow':
                                continue
                            actions = stmt.get('Action', [])
                            if not isinstance(actions, list):
                                actions = [actions]
                            resources = stmt.get('Resource', [])
                            if not isinstance(resources, list):
                                resources = [resources]
                            
                            has_assume = any(a.lower() in ['sts:assumerole', 'sts:*', '*'] for a in actions)
                            has_wildcard = '*' in resources
                            
                            if has_assume and has_wildcard:
                                results.append({
                                    'AccountId': account_id,
                                    'Region': region,
                                    'Service': 'IAM',
                                    'ResourceId': policy['PolicyName'],
                                    'ResourceName': policy['PolicyName'],
                                    'ARN': policy['Arn'],
                                    'Issue': 'sts:AssumeRole with wildcard resource',
                                    'type': 'security',
                                    'Risk': 'Can assume any role in the account - full privilege escalation',
                                    'severity': 'critical',
                                    'check': 'wildcard_assume_role'
                                })
                                break
                    except Exception:
                        continue
        except Exception as e:
            print(f"Error checking wildcard AssumeRole: {e}")
        
        return results
    
    # --- Privilege Escalation Detection (21 patterns) ---

    ESCALATION_PATTERNS = {
        'CreatePolicyVersion': {
            'actions': [['iam:CreatePolicyVersion']],
            'severity': 'critical',
            'risk': 'Can rewrite any customer-managed policy to grant full admin'
        },
        'SetDefaultPolicyVersion': {
            'actions': [['iam:SetDefaultPolicyVersion']],
            'severity': 'critical',
            'risk': 'Can activate an older, more permissive policy version'
        },
        'AttachUserPolicy': {
            'actions': [['iam:AttachUserPolicy']],
            'severity': 'critical',
            'risk': 'Can attach AdministratorAccess to own user'
        },
        'AttachRolePolicy': {
            'actions': [['iam:AttachRolePolicy']],
            'severity': 'critical',
            'risk': 'Can attach admin policy to an assumable role'
        },
        'AttachGroupPolicy': {
            'actions': [['iam:AttachGroupPolicy']],
            'severity': 'critical',
            'risk': 'Can attach admin policy to own group'
        },
        'PutUserPolicy': {
            'actions': [['iam:PutUserPolicy']],
            'severity': 'critical',
            'risk': 'Can create an inline admin policy on own user'
        },
        'PutRolePolicy': {
            'actions': [['iam:PutRolePolicy']],
            'severity': 'critical',
            'risk': 'Can create an inline admin policy on an assumable role'
        },
        'PutGroupPolicy': {
            'actions': [['iam:PutGroupPolicy']],
            'severity': 'critical',
            'risk': 'Can create an inline admin policy on own group'
        },
        'AddUserToGroup': {
            'actions': [['iam:AddUserToGroup']],
            'severity': 'critical',
            'risk': 'Can add self to an admin group'
        },
        'UpdateAssumeRolePolicy': {
            'actions': [['iam:UpdateAssumeRolePolicy']],
            'severity': 'critical',
            'risk': 'Can modify trust policy of an admin role to assume it'
        },
        'CreateLoginProfile': {
            'actions': [['iam:CreateLoginProfile']],
            'severity': 'high',
            'risk': 'Can create console password for another user'
        },
        'UpdateLoginProfile': {
            'actions': [['iam:UpdateLoginProfile']],
            'severity': 'high',
            'risk': 'Can reset console password of another user'
        },
        'CreateAccessKey': {
            'actions': [['iam:CreateAccessKey']],
            'severity': 'high',
            'risk': 'Can create API keys for another user'
        },
        'PassRole+Lambda': {
            'actions': [['iam:PassRole'], ['lambda:CreateFunction', 'lambda:InvokeFunction']],
            'severity': 'high',
            'risk': 'Can launch a Lambda with an admin role and invoke it'
        },
        'PassRole+LambdaUpdate': {
            'actions': [['iam:PassRole'], ['lambda:UpdateFunctionCode']],
            'severity': 'high',
            'risk': 'Can inject code into a Lambda running with a privileged role'
        },
        'PassRole+EC2': {
            'actions': [['iam:PassRole'], ['ec2:RunInstances']],
            'severity': 'high',
            'risk': 'Can launch an EC2 instance with an admin instance profile'
        },
        'PassRole+ECS': {
            'actions': [['iam:PassRole'], ['ecs:RegisterTaskDefinition', 'ecs:RunTask']],
            'severity': 'high',
            'risk': 'Can run an ECS task with an admin task role'
        },
        'PassRole+CloudFormation': {
            'actions': [['iam:PassRole'], ['cloudformation:CreateStack']],
            'severity': 'high',
            'risk': 'Can deploy a CloudFormation stack with an admin service role'
        },
        'PassRole+DataPipeline': {
            'actions': [['iam:PassRole'], ['datapipeline:CreatePipeline']],
            'severity': 'medium',
            'risk': 'Can create a Data Pipeline with a privileged role'
        },
        'PassRole+Glue': {
            'actions': [['iam:PassRole'], ['glue:CreateDevEndpoint']],
            'severity': 'medium',
            'risk': 'Can create a Glue endpoint with a privileged role'
        },
        'AssumeRoleWildcard': {
            'actions': [['sts:AssumeRole']],
            'severity': 'critical',
            'risk': 'Can assume any role in the account'
        }
    }

    def _get_all_actions_for_principal(self, iam, principal_type, principal_name):
        """Collect all allowed actions from inline + attached + group policies"""
        actions = set()
        has_wildcard_resource = False

        def _extract_actions(policy_doc):
            nonlocal has_wildcard_resource
            if isinstance(policy_doc, str):
                policy_doc = json.loads(policy_doc)
            stmts = policy_doc.get('Statement', [])
            if not isinstance(stmts, list):
                stmts = [stmts]
            for stmt in stmts:
                if stmt.get('Effect') != 'Allow':
                    continue
                stmt_actions = stmt.get('Action', [])
                if not isinstance(stmt_actions, list):
                    stmt_actions = [stmt_actions]
                resources = stmt.get('Resource', [])
                if not isinstance(resources, list):
                    resources = [resources]
                if '*' in resources:
                    has_wildcard_resource = True
                for a in stmt_actions:
                    actions.add(a.lower())

        try:
            if principal_type == 'User':
                for pname in iam.list_user_policies(UserName=principal_name).get('PolicyNames', []):
                    doc = iam.get_user_policy(UserName=principal_name, PolicyName=pname)['PolicyDocument']
                    _extract_actions(doc)
                for p in iam.list_attached_user_policies(UserName=principal_name).get('AttachedPolicies', []):
                    if p['PolicyArn'].startswith('arn:aws:iam::aws:'):
                        continue
                    try:
                        pv = iam.get_policy(PolicyArn=p['PolicyArn'])
                        doc = iam.get_policy_version(PolicyArn=p['PolicyArn'], VersionId=pv['Policy']['DefaultVersionId'])['PolicyVersion']['Document']
                        _extract_actions(doc)
                    except Exception:
                        continue
                for g in iam.list_groups_for_user(UserName=principal_name).get('Groups', []):
                    for pname in iam.list_group_policies(GroupName=g['GroupName']).get('PolicyNames', []):
                        doc = iam.get_group_policy(GroupName=g['GroupName'], PolicyName=pname)['PolicyDocument']
                        _extract_actions(doc)
                    for p in iam.list_attached_group_policies(GroupName=g['GroupName']).get('AttachedPolicies', []):
                        if p['PolicyArn'].startswith('arn:aws:iam::aws:'):
                            continue
                        try:
                            pv = iam.get_policy(PolicyArn=p['PolicyArn'])
                            doc = iam.get_policy_version(PolicyArn=p['PolicyArn'], VersionId=pv['Policy']['DefaultVersionId'])['PolicyVersion']['Document']
                            _extract_actions(doc)
                        except Exception:
                            continue
            elif principal_type == 'Role':
                for pname in iam.list_role_policies(RoleName=principal_name).get('PolicyNames', []):
                    doc = iam.get_role_policy(RoleName=principal_name, PolicyName=pname)['PolicyDocument']
                    _extract_actions(doc)
                for p in iam.list_attached_role_policies(RoleName=principal_name).get('AttachedPolicies', []):
                    if p['PolicyArn'].startswith('arn:aws:iam::aws:'):
                        continue
                    try:
                        pv = iam.get_policy(PolicyArn=p['PolicyArn'])
                        doc = iam.get_policy_version(PolicyArn=p['PolicyArn'], VersionId=pv['Policy']['DefaultVersionId'])['PolicyVersion']['Document']
                        _extract_actions(doc)
                    except Exception:
                        continue
        except Exception:
            pass

        return actions, has_wildcard_resource

    def _action_matches(self, principal_actions, required_action):
        """Check if a principal has a required action (supports wildcards like iam:*)"""
        required = required_action.lower()
        service = required.split(':')[0]
        for a in principal_actions:
            if a == '*' or a == required:
                return True
            if a == f'{service}:*':
                return True
        return False

    def _check_pattern_match(self, principal_actions, pattern):
        """Check if principal has all action groups required for an escalation pattern"""
        for action_group in pattern['actions']:
            group_matched = all(self._action_matches(principal_actions, a) for a in action_group)
            if not group_matched:
                return False
        return True

    def _simulate_escalation(self, iam, principal_arn, pattern):
        """Use SimulatePrincipalPolicy to confirm escalation is actually allowed"""
        all_actions = []
        for group in pattern['actions']:
            all_actions.extend(group)

        try:
            result = iam.simulate_principal_policy(
                PolicySourceArn=principal_arn,
                ActionNames=all_actions,
                ResourceArns=['*']
            )
            return all(
                r['EvalDecision'] == 'allowed'
                for r in result['EvaluationResults']
            )
        except Exception:
            return None

    def find_privilege_escalation(self, session: boto3.Session, region: str, deep: bool = False, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Detect IAM principals with privilege escalation paths (21 patterns)"""
        iam = session.client('iam')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []

        principals = []
        try:
            for user in iam.list_users()['Users']:
                principals.append(('User', user['UserName'], user['Arn']))
        except Exception:
            pass
        try:
            for role in iam.list_roles()['Roles']:
                if role['RoleName'].startswith('aws-') or role['RoleName'].startswith('AWSServiceRole'):
                    continue
                principals.append(('Role', role['RoleName'], role['Arn']))
        except Exception:
            pass

        for principal_type, name, arn in principals:
            try:
                actions, has_wildcard_resource = self._get_all_actions_for_principal(iam, principal_type, name)
                if not actions:
                    continue

                # Check permission boundary
                has_boundary = False
                try:
                    if principal_type == 'User':
                        user_detail = iam.get_user(UserName=name)['User']
                        has_boundary = 'PermissionsBoundary' in user_detail
                    else:
                        role_detail = iam.get_role(RoleName=name)['Role']
                        has_boundary = 'PermissionsBoundary' in role_detail
                except Exception:
                    pass

                for pattern_name, pattern in self.ESCALATION_PATTERNS.items():
                    if not self._check_pattern_match(actions, pattern):
                        continue
                    if not has_wildcard_resource and pattern_name != 'AssumeRoleWildcard':
                        continue

                    confirmed = None
                    if deep:
                        confirmed = self._simulate_escalation(iam, arn, pattern)
                        if confirmed is False:
                            continue

                    severity = pattern['severity']
                    if has_boundary and confirmed is None:
                        severity = 'medium'

                    status = ''
                    if deep and confirmed is True:
                        status = ' [CONFIRMED by SimulatePrincipalPolicy]'
                    elif deep and confirmed is None:
                        status = ' [simulation failed, pattern-based]'
                    elif has_boundary:
                        status = ' [boundary may mitigate]'

                    results.append({
                        'AccountId': account_id,
                        'Region': region,
                        'Service': 'IAM',
                        'ResourceId': name,
                        'ResourceName': name,
                        'ARN': arn,
                        'Issue': f'{principal_type} can escalate via {pattern_name}{status}',
                        'type': 'security',
                        'Risk': pattern['risk'],
                        'severity': severity,
                        'check': 'privilege_escalation',
                        'Details': {
                            'PrincipalType': principal_type,
                            'Pattern': pattern_name,
                            'HasPermissionBoundary': has_boundary,
                            'DeepScanConfirmed': confirmed
                        }
                    })
            except Exception:
                continue

        return results

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
    def check_all_users_mfa(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_all_users_mfa(session, region, **kwargs)
    
    def check_root_mfa(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_root_mfa(session, region, **kwargs)
    
    def check_unused_access_keys(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_unused_access_keys(session, region, **kwargs)
    
    def check_inline_policies(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_inline_policies(session, region, **kwargs)
    
    def check_passrole_permissions(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_passrole_permissions(session, region, **kwargs)
    
    def check_shared_lambda_roles(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_shared_lambda_roles(session, region, **kwargs)
    
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

    def check_multiple_active_keys(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_multiple_active_keys(session, region, **kwargs)
    
    def check_wildcard_assume_role(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_wildcard_assume_role(session, region, **kwargs)

    def check_privilege_escalation(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_privilege_escalation(session, region, **kwargs)
