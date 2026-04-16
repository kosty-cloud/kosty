import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any
from datetime import datetime, timedelta
import json


class APIGatewayAuditService:
    def __init__(self):
        self.service_name = "APIGateway"
        self.cost_checks = ['check_unused_apis']
        self.security_checks = [
            'find_no_waf_association', 'find_no_authorization',
            'find_no_access_logging', 'find_no_throttling', 'find_private_api_no_policy',
            'find_http_api_no_jwt', 'find_custom_domain_no_tls12', 'find_missing_request_validation',
            'find_cloudfront_bypass'
        ]
    
    def cost_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all cost-related API Gateway audits"""
        results = []
        for check in self.cost_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def security_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all security-related API Gateway audits"""
        results = []
        for check in self.security_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all API Gateway audits (cost + security)"""
        results = []
        results.extend(self.cost_audit(session, region, config_manager=config_manager, **kwargs))
        results.extend(self.security_audit(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def check_unused_apis(self, session: boto3.Session, region: str, days: int = 30, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find API Gateway APIs with no requests"""
        apigateway = session.client('apigateway', region_name=region)
        cloudwatch = session.client('cloudwatch', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            response = apigateway.get_rest_apis()
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            for api in response['items']:
                try:
                    metrics = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ApiGateway',
                        MetricName='Count',
                        Dimensions=[{'Name': 'ApiName', 'Value': api['name']}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Sum']
                    )
                    
                    total_requests = sum(dp['Sum'] for dp in metrics['Datapoints']) if metrics['Datapoints'] else 0
                    
                    if total_requests == 0:
                        results.append({
                            'AccountId': account_id,
                            'Region': region,
                            'Service': self.service_name,
                            'ResourceId': api['id'],
                            'ResourceName': api['name'],
                            'ResourceArn': f"arn:aws:apigateway:{region}::/restapis/{api['id']}",
                            'Issue': f'API unused (0 requests in {days} days)',
                            'type': 'cost',
                            'Risk': 'Waste $3.50/mo per API',
                            'severity': 'low',
                            'check': 'unused_apis',
                            'Details': {
                                'ApiId': api['id'],
                                'ApiName': api['name'],
                                'CreatedDate': api['createdDate'].isoformat(),
                                'EndpointConfiguration': api.get('endpointConfiguration', {}).get('types', [])
                            }
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking unused APIs: {e}")
        
        return results
    
    # --- Security Checks ---
    
    def find_no_waf_association(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Check if API Gateway stages are protected by a WAF Web ACL"""
        apigateway = session.client('apigateway', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            apis = apigateway.get_rest_apis()
            for api in apis.get('items', []):
                try:
                    stages = apigateway.get_stages(restApiId=api['id'])
                    for stage in stages.get('item', []):
                        waf_acl = stage.get('webAclArn', '')
                        if not waf_acl:
                            results.append({
                                'AccountId': account_id,
                                'Region': region,
                                'Service': self.service_name,
                                'ResourceId': f"{api['name']}/{stage['stageName']}",
                                'ResourceName': f"{api['name']}/{stage['stageName']}",
                                'ARN': f"arn:aws:apigateway:{region}::/restapis/{api['id']}/stages/{stage['stageName']}",
                                'Issue': 'API Gateway stage not protected by WAF',
                                'type': 'security',
                                'Risk': 'No protection against OWASP Top 10, SQLi, XSS',
                                'severity': 'high',
                                'check': 'no_waf_association'
                            })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking API Gateway WAF association: {e}")
        
        return results
    
    def find_no_authorization(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Flag endpoints where authorization type is NONE"""
        apigateway = session.client('apigateway', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            apis = apigateway.get_rest_apis()
            for api in apis.get('items', []):
                try:
                    resources = apigateway.get_resources(restApiId=api['id'])
                    for resource in resources.get('items', []):
                        for method_name, method_info in resource.get('resourceMethods', {}).items():
                            try:
                                method = apigateway.get_method(
                                    restApiId=api['id'],
                                    resourceId=resource['id'],
                                    httpMethod=method_name
                                )
                                auth_type = method.get('authorizationType', 'NONE')
                                if auth_type == 'NONE':
                                    path = resource.get('path', '/')
                                    results.append({
                                        'AccountId': account_id,
                                        'Region': region,
                                        'Service': self.service_name,
                                        'ResourceId': f"{api['name']}:{method_name} {path}",
                                        'ResourceName': f"{api['name']}:{method_name} {path}",
                                        'ARN': f"arn:aws:apigateway:{region}::/restapis/{api['id']}",
                                        'Issue': f'Endpoint {method_name} {path} has no authorization',
                                        'type': 'security',
                                        'Risk': 'Unauthenticated access to backend resources',
                                        'severity': 'high',
                                        'check': 'no_authorization'
                                    })
                            except Exception:
                                continue
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking API Gateway authorization: {e}")
        
        return results
    
    def find_no_access_logging(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Ensure access logging and execution logging are enabled on stages"""
        apigateway = session.client('apigateway', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            apis = apigateway.get_rest_apis()
            for api in apis.get('items', []):
                try:
                    stages = apigateway.get_stages(restApiId=api['id'])
                    for stage in stages.get('item', []):
                        stage_name = stage['stageName']
                        access_log = stage.get('accessLogSettings', {})
                        
                        issues = []
                        if not access_log.get('destinationArn'):
                            issues.append('Access logging disabled')
                        
                        method_settings = stage.get('methodSettings', {})
                        default_settings = method_settings.get('*/*', {})
                        if not default_settings.get('loggingLevel') or default_settings.get('loggingLevel') == 'OFF':
                            issues.append('Execution logging disabled')
                        
                        if issues:
                            results.append({
                                'AccountId': account_id,
                                'Region': region,
                                'Service': self.service_name,
                                'ResourceId': f"{api['name']}/{stage_name}",
                                'ResourceName': f"{api['name']}/{stage_name}",
                                'ARN': f"arn:aws:apigateway:{region}::/restapis/{api['id']}/stages/{stage_name}",
                                'Issue': f"Logging gaps: {', '.join(issues)}",
                                'type': 'security',
                                'Risk': 'No audit trail for API requests - blind to abuse',
                                'severity': 'medium',
                                'check': 'no_access_logging'
                            })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking API Gateway logging: {e}")
        
        return results
    
    def find_no_throttling(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Verify throttling (rate/burst) is configured to prevent cost-bleeding attacks"""
        apigateway = session.client('apigateway', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            apis = apigateway.get_rest_apis()
            for api in apis.get('items', []):
                try:
                    stages = apigateway.get_stages(restApiId=api['id'])
                    for stage in stages.get('item', []):
                        stage_name = stage['stageName']
                        method_settings = stage.get('methodSettings', {})
                        default_settings = method_settings.get('*/*', {})
                        
                        throttle_rate = default_settings.get('throttlingRateLimit', 0)
                        throttle_burst = default_settings.get('throttlingBurstLimit', 0)
                        
                        # AWS defaults are 10000 rps / 5000 burst - flag if using defaults or no override
                        if throttle_rate == 0 or throttle_rate >= 10000:
                            results.append({
                                'AccountId': account_id,
                                'Region': region,
                                'Service': self.service_name,
                                'ResourceId': f"{api['name']}/{stage_name}",
                                'ResourceName': f"{api['name']}/{stage_name}",
                                'ARN': f"arn:aws:apigateway:{region}::/restapis/{api['id']}/stages/{stage_name}",
                                'Issue': 'No custom throttling configured - using AWS defaults or none',
                                'type': 'security',
                                'Risk': 'Cost-bleeding attack via unrestricted API invocations',
                                'severity': 'medium',
                                'check': 'no_throttling',
                                'Details': {
                                    'ThrottleRate': throttle_rate,
                                    'ThrottleBurst': throttle_burst
                                }
                            })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking API Gateway throttling: {e}")
        
        return results
    
    def find_private_api_no_policy(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """For private APIs, verify the presence of a restrictive resource policy"""
        apigateway = session.client('apigateway', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            apis = apigateway.get_rest_apis()
            for api in apis.get('items', []):
                try:
                    endpoint_types = api.get('endpointConfiguration', {}).get('types', [])
                    if 'PRIVATE' not in endpoint_types:
                        continue
                    
                    policy = api.get('policy', '')
                    if not policy:
                        results.append({
                            'AccountId': account_id,
                            'Region': region,
                            'Service': self.service_name,
                            'ResourceId': api['name'],
                            'ResourceName': api['name'],
                            'ARN': f"arn:aws:apigateway:{region}::/restapis/{api['id']}",
                            'Issue': 'Private API has no resource policy',
                            'type': 'security',
                            'Risk': 'Private API accessible from any VPC endpoint without restriction',
                            'severity': 'high',
                            'check': 'private_api_no_policy'
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking private API policies: {e}")
        
        return results
    
    # Individual Check Method Aliases
    def check_no_waf_association(self, session, region, **kwargs):
        return self.find_no_waf_association(session, region, **kwargs)
    
    def check_no_authorization(self, session, region, **kwargs):
        return self.find_no_authorization(session, region, **kwargs)
    
    def check_no_access_logging(self, session, region, **kwargs):
        return self.find_no_access_logging(session, region, **kwargs)
    
    def check_no_throttling(self, session, region, **kwargs):
        return self.find_no_throttling(session, region, **kwargs)
    
    def check_private_api_no_policy(self, session, region, **kwargs):
        return self.find_private_api_no_policy(session, region, **kwargs)
    
    def find_http_api_no_jwt(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find HTTP APIs (v2) without a JWT authorizer"""
        apigwv2 = session.client('apigatewayv2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            apis = apigwv2.get_apis()
            for api in apis.get('Items', []):
                if api.get('ProtocolType') != 'HTTP':
                    continue
                try:
                    authorizers = apigwv2.get_authorizers(ApiId=api['ApiId'])
                    has_jwt = any(
                        a.get('AuthorizerType') == 'JWT'
                        for a in authorizers.get('Items', [])
                    )
                    if not has_jwt:
                        results.append({
                            'AccountId': account_id,
                            'Region': region,
                            'Service': self.service_name,
                            'ResourceId': api.get('Name', api['ApiId']),
                            'ResourceName': api.get('Name', api['ApiId']),
                            'ARN': f"arn:aws:apigateway:{region}::/apis/{api['ApiId']}",
                            'Issue': 'HTTP API has no JWT authorizer configured',
                            'type': 'security',
                            'Risk': 'No token-based authentication on HTTP API routes',
                            'severity': 'high',
                            'check': 'http_api_no_jwt'
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking HTTP API JWT authorizers: {e}")
        
        return results
    
    def check_http_api_no_jwt(self, session, region, **kwargs):
        return self.find_http_api_no_jwt(session, region, **kwargs)
    
    def find_custom_domain_no_tls12(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find custom domains not enforcing TLS 1.2"""
        apigateway = session.client('apigateway', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            domains = apigateway.get_domain_names()
            for domain in domains.get('items', []):
                policy = domain.get('securityPolicy', '')
                if policy != 'TLS_1_2':
                    results.append({
                        'AccountId': account_id,
                        'Region': region,
                        'Service': self.service_name,
                        'ResourceId': domain['domainName'],
                        'ResourceName': domain['domainName'],
                        'ARN': f"arn:aws:apigateway:{region}::/domainnames/{domain['domainName']}",
                        'Issue': f'Custom domain using {policy or "default"} instead of TLS 1.2',
                        'type': 'security',
                        'Risk': 'Vulnerable to downgrade attacks with older TLS versions',
                        'severity': 'medium',
                        'check': 'custom_domain_no_tls12'
                    })
        except Exception as e:
            print(f"Error checking custom domain TLS: {e}")
        
        return results
    
    def check_custom_domain_no_tls12(self, session, region, **kwargs):
        return self.find_custom_domain_no_tls12(session, region, **kwargs)
    
    def find_missing_request_validation(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find REST API methods without request validation"""
        apigateway = session.client('apigateway', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            apis = apigateway.get_rest_apis()
            for api in apis.get('items', []):
                try:
                    validators = apigateway.get_request_validators(restApiId=api['id'])
                    validator_ids = {v['id'] for v in validators.get('items', [])}
                    
                    if not validator_ids:
                        results.append({
                            'AccountId': account_id,
                            'Region': region,
                            'Service': self.service_name,
                            'ResourceId': api['name'],
                            'ResourceName': api['name'],
                            'ARN': f"arn:aws:apigateway:{region}::/restapis/{api['id']}",
                            'Issue': 'No request validators defined on API',
                            'type': 'security',
                            'Risk': 'Malformed requests reach backend without validation',
                            'severity': 'medium',
                            'check': 'missing_request_validation'
                        })
                        continue
                    
                    resources = apigateway.get_resources(restApiId=api['id'])
                    for resource in resources.get('items', []):
                        for method_name in resource.get('resourceMethods', {}):
                            try:
                                method = apigateway.get_method(
                                    restApiId=api['id'],
                                    resourceId=resource['id'],
                                    httpMethod=method_name
                                )
                                if not method.get('requestValidatorId'):
                                    path = resource.get('path', '/')
                                    results.append({
                                        'AccountId': account_id,
                                        'Region': region,
                                        'Service': self.service_name,
                                        'ResourceId': f"{api['name']}:{method_name} {path}",
                                        'ResourceName': f"{api['name']}:{method_name} {path}",
                                        'ARN': f"arn:aws:apigateway:{region}::/restapis/{api['id']}",
                                        'Issue': f'No request validation on {method_name} {path}',
                                        'type': 'security',
                                        'Risk': 'Malformed payloads bypass input checks',
                                        'severity': 'medium',
                                        'check': 'missing_request_validation'
                                    })
                            except Exception:
                                continue
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking request validation: {e}")
        
        return results
    
    def check_missing_request_validation(self, session, region, **kwargs):
        return self.find_missing_request_validation(session, region, **kwargs)
    
    def find_cloudfront_bypass(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find APIs behind CloudFront without a resource policy restricting direct access"""
        apigateway = session.client('apigateway', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        # Build a set of API Gateway origin domains from CloudFront
        cf_api_origins = set()
        try:
            cf = session.client('cloudfront')
            dists = cf.list_distributions()
            if 'DistributionList' in dists and 'Items' in dists['DistributionList']:
                for dist in dists['DistributionList']['Items']:
                    for origin in dist.get('Origins', {}).get('Items', []):
                        domain = origin.get('DomainName', '')
                        if '.execute-api.' in domain:
                            api_id = domain.split('.')[0]
                            cf_api_origins.add(api_id)
        except Exception:
            return results
        
        if not cf_api_origins:
            return results
        
        try:
            for api in apigateway.get_rest_apis().get('items', []):
                if api['id'] not in cf_api_origins:
                    continue
                
                policy_str = api.get('policy', '')
                if not policy_str:
                    results.append(self._build_bypass_finding(
                        account_id, region, api, 'No resource policy — API directly accessible, bypassing CloudFront and WAF'
                    ))
                    continue
                
                try:
                    policy = json.loads(policy_str.replace('\\', ''))
                    has_restriction = False
                    for stmt in policy.get('Statement', []):
                        if stmt.get('Effect') == 'Deny':
                            condition = json.dumps(stmt.get('Condition', {}))
                            if 'aws:Referer' in condition or 'X-Origin-Verify' in condition or 'aws:SourceIp' in condition:
                                has_restriction = True
                                break
                        if stmt.get('Effect') == 'Allow':
                            condition = json.dumps(stmt.get('Condition', {}))
                            if 'aws:SourceIp' in condition or 'aws:SourceVpce' in condition:
                                has_restriction = True
                                break
                    
                    if not has_restriction:
                        results.append(self._build_bypass_finding(
                            account_id, region, api, 'Resource policy exists but does not restrict to CloudFront — direct bypass possible'
                        ))
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking CloudFront bypass: {e}")
        
        return results
    
    def _build_bypass_finding(self, account_id, region, api, issue_detail):
        return {
            'AccountId': account_id,
            'Region': region,
            'Service': self.service_name,
            'ResourceId': api['name'],
            'ResourceName': api['name'],
            'ARN': f"arn:aws:apigateway:{region}::/restapis/{api['id']}",
            'Issue': f'CloudFront bypass: {issue_detail}',
            'type': 'security',
            'Risk': 'Attackers can hit the API directly, bypassing CloudFront WAF protections entirely',
            'severity': 'high',
            'check': 'cloudfront_bypass'
        }
    
    def check_cloudfront_bypass(self, session, region, **kwargs):
        return self.find_cloudfront_bypass(session, region, **kwargs)
