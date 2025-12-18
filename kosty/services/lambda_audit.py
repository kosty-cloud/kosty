import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any
from datetime import datetime, timedelta, timezone

class LambdaAuditService:
    service_name = "Lambda"
    
    cost_checks = [
        "check_unused_functions",
        "check_over_provisioned_memory"
    ]
    
    security_checks = [
        "check_public_functions",
        "check_outdated_runtime"
    ]
    
    def cost_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run Lambda cost optimization audit"""
        results = []
        for check in self.cost_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def security_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run Lambda security audit"""
        results = []
        for check in self.security_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run complete Lambda audit"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        results.extend(self.check_long_timeout_functions(session, region, **kwargs))
        return results

    def check_unused_functions(self, session: boto3.Session, region: str, days: int = 30, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find Lambda functions with 0 invocations in X days"""
        lambda_client = session.client('lambda', region_name=region)
        cloudwatch = session.client('cloudwatch', region_name=region)
        results = []
        
        try:
            response = lambda_client.list_functions()
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            for function in response['Functions']:
                try:
                    # Get invocation metrics
                    metrics_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/Lambda',
                        MetricName='Invocations',
                        Dimensions=[
                            {'Name': 'FunctionName', 'Value': function['FunctionName']}
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Sum']
                    )
                    
                    total_invocations = sum(point['Sum'] for point in metrics_response['Datapoints'])
                    
                    if total_invocations == 0:
                        results.append({
                            'AccountId': session.client('sts').get_caller_identity()['Account'],
                            'Region': region,
                            'Service': self.service_name,
                            'ResourceId': function['FunctionName'],
                            'ResourceName': function['FunctionName'],
                            'Issue': 'Unused Lambda function',
                            'type': 'cost',
                            'Risk': 'LOW',
                            'severity': 'low',
                            'Description': f"Lambda function {function['FunctionName']} has 0 invocations in {days} days",
                            'ARN': function['FunctionArn'],
                            'Details': {
                                'FunctionName': function['FunctionName'],
                                'Runtime': function.get('Runtime'),
                                'MemorySize': function.get('MemorySize'),
                                'LastModified': function.get('LastModified'),
                                'TotalInvocations': total_invocations
                            }
                        })
                except Exception as e:
                    print(f"Error checking function {function['FunctionName']}: {e}")
                    continue
        except Exception as e:
            print(f"Error checking unused Lambda functions in {region}: {e}")
        
        return results

    def check_over_provisioned_memory(self, session: boto3.Session, region: str, days: int = 30, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find Lambda functions with over-provisioned memory"""
        lambda_client = session.client('lambda', region_name=region)
        cloudwatch = session.client('cloudwatch', region_name=region)
        results = []
        
        try:
            response = lambda_client.list_functions()
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            for function in response['Functions']:
                try:
                    # Get memory utilization metrics
                    metrics_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/Lambda',
                        MetricName='Duration',
                        Dimensions=[
                            {'Name': 'FunctionName', 'Value': function['FunctionName']}
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Average']
                    )
                    
                    if metrics_response['Datapoints']:
                        avg_duration = sum(point['Average'] for point in metrics_response['Datapoints']) / len(metrics_response['Datapoints'])
                        memory_size = function.get('MemorySize', 128)
                        timeout = function.get('Timeout', 3)
                        
                        # Get invocation count for cost calculation
                        invocation_metrics = cloudwatch.get_metric_statistics(
                            Namespace='AWS/Lambda',
                            MetricName='Invocations',
                            Dimensions=[
                                {'Name': 'FunctionName', 'Value': function['FunctionName']}
                            ],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=86400,
                            Statistics=['Sum']
                        )
                        
                        total_invocations = sum(point['Sum'] for point in invocation_metrics['Datapoints']) if invocation_metrics['Datapoints'] else 0
                        
                        # If duration is very low compared to timeout, memory might be over-provisioned
                        if avg_duration < (timeout * 1000 * 0.2) and memory_size > 512:  # Less than 20% of timeout used and >512MB
                            results.append({
                                'AccountId': session.client('sts').get_caller_identity()['Account'],
                                'Region': region,
                                'region': region,
                                'Service': self.service_name,
                                'service': 'Lambda',
                                'ResourceId': function['FunctionName'],
                                'ResourceName': function['FunctionName'],
                                'Issue': 'Over-provisioned Lambda memory',
                                'type': 'cost',
                                'Risk': 'MEDIUM',
                                'severity': 'medium',
                                'check': 'over_provisioned_memory',
                                'memory_mb': memory_size,
                                'invocations': int(total_invocations),
                                'avg_duration_ms': int(avg_duration),
                                'resource_id': function['FunctionName'],
                                'resource_name': function['FunctionName'],
                                'Description': f"Lambda function {function['FunctionName']} may have over-provisioned memory",
                                'ARN': function['FunctionArn'],
                                'Details': {
                                    'FunctionName': function['FunctionName'],
                                    'MemorySize': memory_size,
                                    'AvgDuration': round(avg_duration, 2),
                                    'Timeout': timeout,
                                    'TotalInvocations': int(total_invocations)
                                }
                            })
                except Exception as e:
                    print(f"Error checking function {function['FunctionName']}: {e}")
                    continue
        except Exception as e:
            print(f"Error checking over-provisioned Lambda functions in {region}: {e}")
        
        return results

    def check_public_functions(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find Lambda functions with public access"""
        lambda_client = session.client('lambda', region_name=region)
        results = []
        
        try:
            response = lambda_client.list_functions()
            
            for function in response['Functions']:
                try:
                    # Check function policy for public access
                    policy_response = lambda_client.get_policy(FunctionName=function['FunctionName'])
                    policy = policy_response.get('Policy', '{}')
                    
                    # Simple check for wildcard principals
                    if '"*"' in policy or '"Principal":"*"' in policy:
                        results.append({
                            'AccountId': session.client('sts').get_caller_identity()['Account'],
                            'Region': region,
                            'Service': self.service_name,
                            'ResourceId': function['FunctionName'],
                            'ResourceName': function['FunctionName'],
                            'Issue': 'Publicly accessible Lambda function',
                            'type': 'security',
                            'Risk': 'HIGH',
                            'severity': 'high',
                            'Description': f"Lambda function {function['FunctionName']} allows public access",
                            'ARN': function['FunctionArn'],
                            'Details': {
                                'FunctionName': function['FunctionName'],
                                'Runtime': function.get('Runtime'),
                                'HasPublicPolicy': True
                            }
                        })
                except lambda_client.exceptions.ResourceNotFoundException:
                    # No policy attached, which is good
                    continue
                except Exception as e:
                    print(f"Error checking function policy {function['FunctionName']}: {e}")
                    continue
        except Exception as e:
            print(f"Error checking public Lambda functions in {region}: {e}")
        
        return results

    def check_outdated_runtime(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find Lambda functions using outdated runtimes"""
        lambda_client = session.client('lambda', region_name=region)
        results = []
        
        # Define outdated runtimes
        outdated_runtimes = [
            'python2.7', 'python3.6', 'python3.7',
            'nodejs8.10', 'nodejs10.x', 'nodejs12.x',
            'dotnetcore2.1', 'dotnetcore3.1',
            'go1.x',
            'ruby2.5', 'ruby2.7'
        ]
        
        try:
            response = lambda_client.list_functions()
            
            for function in response['Functions']:
                runtime = function.get('Runtime', '')
                
                if runtime in outdated_runtimes:
                    results.append({
                        'AccountId': session.client('sts').get_caller_identity()['Account'],
                        'Region': region,
                        'Service': self.service_name,
                        'ResourceId': function['FunctionName'],
                        'ResourceName': function['FunctionName'],
                        'Issue': 'Outdated Lambda runtime',
                        'type': 'security',
                        'Risk': 'MEDIUM',
                        'severity': 'medium',
                        'Description': f"Lambda function {function['FunctionName']} uses outdated runtime {runtime}",
                        'ARN': function['FunctionArn'],
                        'Details': {
                            'FunctionName': function['FunctionName'],
                            'Runtime': runtime,
                            'LastModified': function.get('LastModified')
                        }
                    })
        except Exception as e:
            print(f"Error checking outdated Lambda runtimes in {region}: {e}")
        
        return results

    def check_long_timeout_functions(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find Lambda functions with timeout >5min (anti-pattern)"""
        lambda_client = session.client('lambda', region_name=region)
        results = []
        
        try:
            response = lambda_client.list_functions()
            
            for function in response['Functions']:
                timeout = function.get('Timeout', 3)
                
                if timeout > 300:  # 5 minutes
                    results.append({
                        'AccountId': session.client('sts').get_caller_identity()['Account'],
                        'Region': region,
                        'Service': self.service_name,
                        'ResourceId': function['FunctionName'],
                        'ResourceName': function['FunctionName'],
                        'Issue': 'Long timeout Lambda function',
                        'type': 'cost',
                        'Risk': 'LOW',
                        'severity': 'low',
                        'Description': f"Lambda function {function['FunctionName']} has timeout >5min (consider ECS/Fargate)",
                        'ARN': function['FunctionArn'],
                        'Details': {
                            'FunctionName': function['FunctionName'],
                            'Timeout': timeout,
                            'Runtime': function.get('Runtime'),
                            'MemorySize': function.get('MemorySize')
                        }
                    })
        except Exception as e:
            print(f"Error checking long timeout Lambda functions in {region}: {e}")
        
        return results

