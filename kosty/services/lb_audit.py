import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any
from datetime import datetime, timedelta
import json

class LBAuditService:
    def __init__(self):
        self.service_name = "LB"
        self.cost_checks = ['find_lbs_with_no_healthy_targets', 'find_underutilized_lbs', 'find_classic_lbs']
        self.security_checks = ['find_http_without_https_redirect', 'find_deprecated_tls_versions', 'find_lbs_without_access_logs']

    def cost_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all cost-related Load Balancer audits"""
        results = []
        for check in self.cost_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results

    def security_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all security-related Load Balancer audits"""
        results = []
        for check in self.security_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results

    def audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all Load Balancer audits"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        return results

    def find_lbs_with_no_healthy_targets(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find load balancers with no healthy targets"""
        elbv2 = session.client('elbv2', region_name=region)
        results = []
        
        try:
            # Get all ALBs and NLBs
            lbs_response = elbv2.describe_load_balancers()
            
            for lb in lbs_response['LoadBalancers']:
                lb_arn = lb['LoadBalancerArn']
                
                # Get target groups for this LB
                tgs_response = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)
                
                has_healthy_targets = False
                for tg in tgs_response['TargetGroups']:
                    # Check target health
                    health_response = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                    
                    for target in health_response['TargetHealthDescriptions']:
                        if target['TargetHealth']['State'] == 'healthy':
                            has_healthy_targets = True
                            break
                    
                    if has_healthy_targets:
                        break
                
                if not has_healthy_targets:
                    results.append({
                        'AccountId': session.client('sts').get_caller_identity()['Account'],
                        'Region': region,
                        'region': region,
                        'Service': self.service_name,
                        'service': 'LoadBalancer',
                        'ResourceId': lb['LoadBalancerName'],
                        'resource_id': lb['LoadBalancerName'],
                        'resource_name': lb['LoadBalancerName'],
                        'ResourceArn': lb_arn,
                        'Issue': 'Load balancer with no healthy targets',
                        'type': 'cost',
                        'check': 'no_healthy_targets',
                        'Risk': 'Waste $270-360/year per LB',
                        'severity': 'high',
                        'Details': {
                            'LoadBalancerName': lb['LoadBalancerName'],
                            'Type': lb['Type'],
                            'Scheme': lb['Scheme'],
                            'State': lb['State']['Code']
                        }
                    })
        except Exception as e:
            pass
        
        return results

    def find_underutilized_lbs(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find load balancers with low request count"""
        elbv2 = session.client('elbv2', region_name=region)
        cloudwatch = session.client('cloudwatch', region_name=region)
        results = []
        
        try:
            lbs_response = elbv2.describe_load_balancers()
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=7)
            
            for lb in lbs_response['LoadBalancers']:
                try:
                    # Get request count metrics
                    metrics_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ApplicationELB',
                        MetricName='RequestCount',
                        Dimensions=[
                            {'Name': 'LoadBalancer', 'Value': lb['LoadBalancerArn'].split('/')[-3] + '/' + lb['LoadBalancerArn'].split('/')[-2] + '/' + lb['LoadBalancerArn'].split('/')[-1]}
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,  # 1 day
                        Statistics=['Sum']
                    )
                    
                    total_requests = sum(point['Sum'] for point in metrics_response['Datapoints'])
                    avg_requests_per_day = total_requests / 7 if total_requests > 0 else 0
                    
                    if avg_requests_per_day < 100:
                        results.append({
                            'AccountId': session.client('sts').get_caller_identity()['Account'],
                            'Region': region,
                            'Service': self.service_name,
                            'ResourceId': lb['LoadBalancerName'],
                            'ResourceArn': lb['LoadBalancerArn'],
                            'Issue': 'Load balancer with <100 requests/day',
                            'type': 'cost',
                            'Risk': 'Underutilized - waste 80%+',
                            'severity': 'medium',
                            'Details': {
                                'LoadBalancerName': lb['LoadBalancerName'],
                                'Type': lb['Type'],
                                'AvgRequestsPerDay': round(avg_requests_per_day, 2)
                            }
                        })
                except Exception:
                    continue
        except Exception as e:
            pass
        
        return results

    def find_http_without_https_redirect(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find HTTP listeners without HTTPS redirect"""
        elbv2 = session.client('elbv2', region_name=region)
        results = []
        
        try:
            lbs_response = elbv2.describe_load_balancers()
            
            for lb in lbs_response['LoadBalancers']:
                if lb['Type'] != 'application':  # Only ALBs support HTTP/HTTPS
                    continue
                
                listeners_response = elbv2.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
                
                for listener in listeners_response['Listeners']:
                    if listener['Protocol'] == 'HTTP':
                        # Check if default action is redirect to HTTPS
                        has_https_redirect = False
                        for action in listener['DefaultActions']:
                            if (action['Type'] == 'redirect' and 
                                action.get('RedirectConfig', {}).get('Protocol') == 'HTTPS'):
                                has_https_redirect = True
                                break
                        
                        if not has_https_redirect:
                            results.append({
                                'AccountId': session.client('sts').get_caller_identity()['Account'],
                                'Region': region,
                                'Service': self.service_name,
                                'ResourceId': lb['LoadBalancerName'],
                                'ResourceArn': lb['LoadBalancerArn'],
                                'Issue': 'HTTP listener without HTTPS redirect',
                                'type': 'security',
                                'Risk': 'Man-in-the-middle attacks',
                                'severity': 'high',
                                'Details': {
                                    'LoadBalancerName': lb['LoadBalancerName'],
                                    'ListenerArn': listener['ListenerArn'],
                                    'Port': listener['Port']
                                }
                            })
        except Exception as e:
            pass
        
        return results

    def find_deprecated_tls_versions(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find load balancers with deprecated TLS versions enabled"""
        elbv2 = session.client('elbv2', region_name=region)
        results = []
        
        try:
            lbs_response = elbv2.describe_load_balancers()
            
            for lb in lbs_response['LoadBalancers']:
                if lb['Type'] != 'application':
                    continue
                
                listeners_response = elbv2.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
                
                for listener in listeners_response['Listeners']:
                    if listener['Protocol'] == 'HTTPS':
                        # Check SSL policy
                        ssl_policy = listener.get('SslPolicy', '')
                        
                        # Policies that support TLS 1.0/1.1
                        deprecated_policies = [
                            'ELBSecurityPolicy-2016-08',
                            'ELBSecurityPolicy-TLS-1-0-2015-04',
                            'ELBSecurityPolicy-TLS-1-1-2017-01'
                        ]
                        
                        if any(policy in ssl_policy for policy in deprecated_policies):
                            results.append({
                                'AccountId': session.client('sts').get_caller_identity()['Account'],
                                'Region': region,
                                'Service': self.service_name,
                                'ResourceId': lb['LoadBalancerName'],
                                'ResourceArn': lb['LoadBalancerArn'],
                                'Issue': 'TLS 1.0/1.1 enabled',
                                'type': 'security',
                                'Risk': 'Deprecated protocols vulnerable',
                                'severity': 'medium',
                                'Details': {
                                    'LoadBalancerName': lb['LoadBalancerName'],
                                    'ListenerArn': listener['ListenerArn'],
                                    'SslPolicy': ssl_policy
                                }
                            })
        except Exception as e:
            pass
        
        return results

    def find_lbs_without_access_logs(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find load balancers without access logs enabled"""
        elbv2 = session.client('elbv2', region_name=region)
        results = []
        
        try:
            lbs_response = elbv2.describe_load_balancers()
            
            for lb in lbs_response['LoadBalancers']:
                # Get load balancer attributes
                attrs_response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb['LoadBalancerArn'])
                
                access_logs_enabled = False
                for attr in attrs_response['Attributes']:
                    if attr['Key'] == 'access_logs.s3.enabled' and attr['Value'] == 'true':
                        access_logs_enabled = True
                        break
                
                if not access_logs_enabled:
                    results.append({
                        'AccountId': session.client('sts').get_caller_identity()['Account'],
                        'Region': region,
                        'Service': self.service_name,
                        'ResourceId': lb['LoadBalancerName'],
                        'ResourceArn': lb['LoadBalancerArn'],
                        'Issue': 'No access logs enabled',
                        'type': 'security',
                        'Risk': 'Cannot audit traffic/attacks',
                        'severity': 'low',
                        'Details': {
                            'LoadBalancerName': lb['LoadBalancerName'],
                            'Type': lb['Type'],
                            'Scheme': lb['Scheme']
                        }
                    })
        except Exception as e:
            pass
        
        return results

    def find_classic_lbs(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find Classic Load Balancers (should use ALB/NLB)"""
        elb = session.client('elb', region_name=region)
        results = []
        
        try:
            lbs_response = elb.describe_load_balancers()
            
            for lb in lbs_response['LoadBalancerDescriptions']:
                results.append({
                    'AccountId': session.client('sts').get_caller_identity()['Account'],
                    'Region': region,
                    'Service': self.service_name,
                    'ResourceId': lb['LoadBalancerName'],
                    'ResourceArn': f"arn:aws:elasticloadbalancing:{region}:{session.client('sts').get_caller_identity()['Account']}:loadbalancer/{lb['LoadBalancerName']}",
                    'Issue': 'Classic LB (not ALB/NLB)',
                    'type': 'cost',
                    'Risk': 'Waste 10-30% vs modern LBs',
                    'severity': 'low',
                    'Details': {
                        'LoadBalancerName': lb['LoadBalancerName'],
                        'Scheme': lb['Scheme'],
                        'CreatedTime': lb['CreatedTime'].isoformat() if 'CreatedTime' in lb else None
                    }
                })
        except Exception as e:
            pass
        
        return results

    # Individual check aliases
    def check_lbs_with_no_healthy_targets(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        return self.find_lbs_with_no_healthy_targets(session, region)
    
    def check_underutilized_lbs(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        return self.find_underutilized_lbs(session, region)
    
    def check_http_without_https_redirect(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        return self.find_http_without_https_redirect(session, region)
    
    def check_deprecated_tls_versions(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        return self.find_deprecated_tls_versions(session, region)
    
    def check_lbs_without_access_logs(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        return self.find_lbs_without_access_logs(session, region)
    
    def check_classic_lbs(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        return self.find_classic_lbs(session, region)