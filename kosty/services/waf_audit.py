import boto3
from typing import List, Dict, Any
import json


class WAFAuditService:
    def __init__(self):
        self.cost_checks = []
        self.security_checks = [
            'find_unassociated_acls', 'find_missing_managed_rules',
            'find_no_rate_based_rule', 'find_no_logging', 'find_default_count_action',
            'find_no_bot_control'
        ]
    
    def find_unassociated_acls(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find WAFv2 Web ACLs not associated with any resource"""
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        scopes = [('REGIONAL', region)]
        if region == 'us-east-1':
            scopes.append(('CLOUDFRONT', 'us-east-1'))
        
        for scope, reg in scopes:
            try:
                waf = session.client('wafv2', region_name=reg)
                acls = waf.list_web_acls(Scope=scope)
                
                for acl in acls.get('WebACLs', []):
                    try:
                        resources = waf.list_resources_for_web_acl(
                            WebACLArn=acl['ARN'],
                            ResourceType='APPLICATION_LOAD_BALANCER'
                        )
                        alb_count = len(resources.get('ResourceArns', []))
                        
                        apigw_count = 0
                        try:
                            apigw_resources = waf.list_resources_for_web_acl(
                                WebACLArn=acl['ARN'],
                                ResourceType='API_GATEWAY'
                            )
                            apigw_count = len(apigw_resources.get('ResourceArns', []))
                        except Exception:
                            pass
                        
                        total = alb_count + apigw_count
                        if total == 0:
                            results.append({
                                'AccountId': account_id,
                                'Region': region,
                                'Service': 'WAF',
                                'ResourceId': acl['Name'],
                                'ResourceName': acl['Name'],
                                'ARN': acl['ARN'],
                                'Issue': f'Web ACL not associated with any resource (scope: {scope})',
                                'type': 'security',
                                'Risk': 'WAF rules have no effect if not attached to a resource',
                                'severity': 'high',
                                'check': 'unassociated_acls'
                            })
                    except Exception:
                        continue
            except Exception as e:
                print(f"Error checking WAF ACLs ({scope}): {e}")
        
        return results
    
    def find_missing_managed_rules(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Verify presence of AWS Managed Rules (Core Rule Set & IP Reputation)"""
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        required_groups = {
            'AWSManagedRulesCommonRuleSet': 'Core Rule Set (XSS, SQLi, LFI)',
            'AWSManagedRulesAmazonIpReputationList': 'IP Reputation List',
            'AWSManagedRulesSQLiRuleSet': 'SQL Injection Rule Set',
            'AWSManagedRulesKnownBadInputsRuleSet': 'Known Bad Inputs (Log4j, etc.)'
        }
        
        scopes = [('REGIONAL', region)]
        if region == 'us-east-1':
            scopes.append(('CLOUDFRONT', 'us-east-1'))
        
        for scope, reg in scopes:
            try:
                waf = session.client('wafv2', region_name=reg)
                acls = waf.list_web_acls(Scope=scope)
                
                for acl in acls.get('WebACLs', []):
                    try:
                        detail = waf.get_web_acl(Name=acl['Name'], Scope=scope, Id=acl['Id'])
                        rules = detail['WebACL'].get('Rules', [])
                        
                        managed_groups = set()
                        for rule in rules:
                            stmt = rule.get('Statement', {})
                            mgr = stmt.get('ManagedRuleGroupStatement', {})
                            if mgr.get('VendorName') == 'AWS':
                                managed_groups.add(mgr.get('Name'))
                        
                        for group_name, description in required_groups.items():
                            if group_name not in managed_groups:
                                results.append({
                                    'AccountId': account_id,
                                    'Region': region,
                                    'Service': 'WAF',
                                    'ResourceId': acl['Name'],
                                    'ResourceName': acl['Name'],
                                    'ARN': acl['ARN'],
                                    'Issue': f'Missing AWS Managed Rule: {description}',
                                    'type': 'security',
                                    'Risk': f'No protection from {description} attack vectors',
                                    'severity': 'high',
                                    'check': 'missing_managed_rules'
                                })
                    except Exception:
                        continue
            except Exception as e:
                print(f"Error checking WAF managed rules ({scope}): {e}")
        
        return results
    
    def find_no_rate_based_rule(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check for rate-based rules to mitigate DDoS and brute-force attacks"""
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        scopes = [('REGIONAL', region)]
        if region == 'us-east-1':
            scopes.append(('CLOUDFRONT', 'us-east-1'))
        
        for scope, reg in scopes:
            try:
                waf = session.client('wafv2', region_name=reg)
                acls = waf.list_web_acls(Scope=scope)
                
                for acl in acls.get('WebACLs', []):
                    try:
                        detail = waf.get_web_acl(Name=acl['Name'], Scope=scope, Id=acl['Id'])
                        rules = detail['WebACL'].get('Rules', [])
                        
                        has_rate_rule = any(
                            'RateBasedStatement' in rule.get('Statement', {})
                            for rule in rules
                        )
                        
                        if not has_rate_rule:
                            results.append({
                                'AccountId': account_id,
                                'Region': region,
                                'Service': 'WAF',
                                'ResourceId': acl['Name'],
                                'ResourceName': acl['Name'],
                                'ARN': acl['ARN'],
                                'Issue': 'No rate-based rule configured - DDoS/brute-force exposure',
                                'type': 'security',
                                'Risk': 'No automated throttling against volumetric attacks',
                                'severity': 'critical',
                                'check': 'no_rate_based_rule'
                            })
                    except Exception:
                        continue
            except Exception as e:
                print(f"Error checking WAF rate rules ({scope}): {e}")
        
        return results
    
    def find_no_logging(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Verify WAF logging is enabled"""
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        scopes = [('REGIONAL', region)]
        if region == 'us-east-1':
            scopes.append(('CLOUDFRONT', 'us-east-1'))
        
        for scope, reg in scopes:
            try:
                waf = session.client('wafv2', region_name=reg)
                acls = waf.list_web_acls(Scope=scope)
                
                for acl in acls.get('WebACLs', []):
                    try:
                        waf.get_logging_configuration(ResourceArn=acl['ARN'])
                    except waf.exceptions.WAFNonexistentItemException:
                        results.append({
                            'AccountId': account_id,
                            'Region': region,
                            'Service': 'WAF',
                            'ResourceId': acl['Name'],
                            'ResourceName': acl['Name'],
                            'ARN': acl['ARN'],
                            'Issue': 'WAF logging is not enabled',
                            'type': 'security',
                            'Risk': 'No visibility into blocked or allowed requests for forensics',
                            'severity': 'high',
                            'check': 'no_logging'
                        })
                    except Exception:
                        continue
            except Exception as e:
                print(f"Error checking WAF logging ({scope}): {e}")
        
        return results
    
    def find_default_count_action(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Ensure default action is not Count for critical managed rules"""
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        critical_groups = ['AWSManagedRulesCommonRuleSet', 'AWSManagedRulesSQLiRuleSet',
                           'AWSManagedRulesKnownBadInputsRuleSet']
        
        scopes = [('REGIONAL', region)]
        if region == 'us-east-1':
            scopes.append(('CLOUDFRONT', 'us-east-1'))
        
        for scope, reg in scopes:
            try:
                waf = session.client('wafv2', region_name=reg)
                acls = waf.list_web_acls(Scope=scope)
                
                for acl in acls.get('WebACLs', []):
                    try:
                        detail = waf.get_web_acl(Name=acl['Name'], Scope=scope, Id=acl['Id'])
                        rules = detail['WebACL'].get('Rules', [])
                        
                        for rule in rules:
                            stmt = rule.get('Statement', {})
                            mgr = stmt.get('ManagedRuleGroupStatement', {})
                            group_name = mgr.get('Name', '')
                            
                            if group_name in critical_groups:
                                action = rule.get('OverrideAction', {})
                                if 'Count' in action or 'count' in action:
                                    results.append({
                                        'AccountId': account_id,
                                        'Region': region,
                                        'Service': 'WAF',
                                        'ResourceId': acl['Name'],
                                        'ResourceName': acl['Name'],
                                        'ARN': acl['ARN'],
                                        'Issue': f'Critical rule group "{group_name}" set to Count instead of Block',
                                        'type': 'security',
                                        'Risk': 'Attacks are logged but not blocked - false sense of security',
                                        'severity': 'high',
                                        'check': 'default_count_action'
                                    })
                    except Exception:
                        continue
            except Exception as e:
                print(f"Error checking WAF default actions ({scope}): {e}")
        
        return results
    
    # Audit Methods
    def cost_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all cost-related audits"""
        results = []
        for check in self.cost_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def security_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all security-related audits"""
        results = []
        for check in self.security_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all audits (cost + security)"""
        results = []
        results.extend(self.cost_audit(session, region, config_manager=config_manager, **kwargs))
        results.extend(self.security_audit(session, region, config_manager=config_manager, **kwargs))
        return results
    
    # Individual Check Method Aliases
    def check_unassociated_acls(self, session, region, **kwargs):
        return self.find_unassociated_acls(session, region, **kwargs)
    
    def check_missing_managed_rules(self, session, region, **kwargs):
        return self.find_missing_managed_rules(session, region, **kwargs)
    
    def check_no_rate_based_rule(self, session, region, **kwargs):
        return self.find_no_rate_based_rule(session, region, **kwargs)
    
    def check_no_logging(self, session, region, **kwargs):
        return self.find_no_logging(session, region, **kwargs)
    
    def check_default_count_action(self, session, region, **kwargs):
        return self.find_default_count_action(session, region, **kwargs)
    
    def find_no_bot_control(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check for AWS Bot Control managed rule group"""
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        scopes = [('REGIONAL', region)]
        if region == 'us-east-1':
            scopes.append(('CLOUDFRONT', 'us-east-1'))
        
        for scope, reg in scopes:
            try:
                waf = session.client('wafv2', region_name=reg)
                acls = waf.list_web_acls(Scope=scope)
                
                for acl in acls.get('WebACLs', []):
                    try:
                        detail = waf.get_web_acl(Name=acl['Name'], Scope=scope, Id=acl['Id'])
                        rules = detail['WebACL'].get('Rules', [])
                        
                        has_bot_control = any(
                            rule.get('Statement', {}).get('ManagedRuleGroupStatement', {}).get('Name') == 'AWSManagedRulesBotControlRuleSet'
                            for rule in rules
                        )
                        
                        if not has_bot_control:
                            results.append({
                                'AccountId': account_id,
                                'Region': region,
                                'Service': 'WAF',
                                'ResourceId': acl['Name'],
                                'ResourceName': acl['Name'],
                                'ARN': acl['ARN'],
                                'Issue': 'No Bot Control rule group configured',
                                'type': 'security',
                                'Risk': 'No protection against scrapers, crawlers, and automated abuse',
                                'severity': 'medium',
                                'check': 'no_bot_control'
                            })
                    except Exception:
                        continue
            except Exception as e:
                print(f"Error checking WAF Bot Control ({scope}): {e}")
        
        return results
    
    def check_no_bot_control(self, session, region, **kwargs):
        return self.find_no_bot_control(session, region, **kwargs)
