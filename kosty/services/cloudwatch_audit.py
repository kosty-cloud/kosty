import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any
from datetime import datetime, timedelta

class CloudWatchAuditService:
    def __init__(self):
        self.service_name = "CloudWatch"
        self.cost_checks = ['check_log_groups_without_retention', 'check_unused_alarms', 'check_unused_custom_metrics']
        self.security_checks = []  # No security checks for CloudWatch

    def cost_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run cost-related audits"""
        results = []
        for check in self.cost_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def security_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run security-related audits"""
        return []  # No security checks for CloudWatch
    
    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run complete CloudWatch audit (cost + security)"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        return results
    
    def check_log_groups_without_retention(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find log groups without retention policy"""
        logs = session.client('logs', region_name=region)
        results = []
        
        try:
            paginator = logs.get_paginator('describe_log_groups')
            
            for page in paginator.paginate():
                for log_group in page['logGroups']:
                    retention_days = log_group.get('retentionInDays')
                    stored_bytes = log_group.get('storedBytes', 0)
                    
                    if not retention_days:
                        monthly_cost = (stored_bytes / (1024**3)) * 0.50 if stored_bytes > 0 else 0
                        
                        results.append({
                            'AccountId': session.client('sts').get_caller_identity()['Account'],
                            'Region': region,
                            'Service': self.service_name,
                            'ResourceId': log_group['logGroupName'],
                            'ResourceName': log_group['logGroupName'],
                            'Issue': 'Log group without retention policy',
                            'type': 'cost',
                            'Risk': 'HIGH' if stored_bytes > 1024**3 else 'MEDIUM',
                            'severity': 'high' if stored_bytes > 1024**3 else 'Medium',
                            'Description': f"Log group {log_group['logGroupName']} has no retention policy and costs ${round(monthly_cost, 2)}/month",
                            'ARN': log_group['arn'],
                            'Details': {
                                'LogGroupName': log_group['logGroupName'],
                                'CreationTime': datetime.fromtimestamp(log_group['creationTime'] / 1000).isoformat(),
                                'StoredBytes': stored_bytes,
                                'StoredGB': round(stored_bytes / (1024**3), 2),
                                'EstimatedMonthlyCost': round(monthly_cost, 2)
                            }
                        })
        except Exception as e:
            print(f"Error checking CloudWatch log groups in {region}: {e}")
        
        return results

    def check_unused_alarms(self, session: boto3.Session, region: str, days: int = 30, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find unused CloudWatch alarms (no state changes in X days)"""
        cloudwatch = session.client('cloudwatch', region_name=region)
        results = []
        
        try:
            paginator = cloudwatch.get_paginator('describe_alarms')
            cutoff_date = datetime.utcnow().replace(tzinfo=None) - timedelta(days=days)
            
            for page in paginator.paginate():
                for alarm in page['MetricAlarms']:
                    state_updated = alarm.get('StateUpdatedTimestamp')
                    
                    if state_updated and state_updated.replace(tzinfo=None) < cutoff_date:
                        results.append({
                            'AccountId': session.client('sts').get_caller_identity()['Account'],
                            'Region': region,
                            'Service': self.service_name,
                            'ResourceId': alarm['AlarmName'],
                            'ResourceName': alarm['AlarmName'],
                            'Issue': 'Unused CloudWatch alarm',
                            'type': 'cost',
                            'Risk': 'LOW',
                            'severity': 'low',
                            'Description': f"CloudWatch alarm {alarm['AlarmName']} has no state changes in {days} days",
                            'ARN': alarm['AlarmArn'],
                            'Details': {
                                'AlarmName': alarm['AlarmName'],
                                'StateValue': alarm.get('StateValue'),
                                'StateUpdatedTimestamp': state_updated.isoformat() if state_updated else None,
                                'MetricName': alarm.get('MetricName')
                            }
                        })
        except Exception as e:
            print(f"Error checking CloudWatch alarms in {region}: {e}")
        
        return results

    def check_unused_custom_metrics(self, session: boto3.Session, region: str, days: int = 30, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find unused custom metrics (no data in X days)"""
       
        cloudwatch = session.client('cloudwatch', region_name=region)
        results = []
        
        try:
            paginator = cloudwatch.get_paginator('list_metrics')
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            for page in paginator.paginate():
                for metric in page['Metrics']:
                    namespace = metric['Namespace']
                    
                    if namespace.startswith('AWS/'):
                        continue
                    
                    try:
                        stats_response = cloudwatch.get_metric_statistics(
                            Namespace=namespace,
                            MetricName=metric['MetricName'],
                            Dimensions=metric.get('Dimensions', []),
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=86400,
                            Statistics=['SampleCount']
                        )
                        
                        if not stats_response['Datapoints']:
                            metric_name = f"{namespace}/{metric['MetricName']}"
                            results.append({
                                'AccountId': session.client('sts').get_caller_identity()['Account'],
                                'Region': region,
                                'Service': self.service_name,
                                'ResourceId': metric_name,
                                'ResourceName': metric_name,
                                'Issue': 'Unused custom metric',
                                'type': 'cost',
                                'Risk': 'LOW',
                                'severity': 'low',
                                'Description': f"Custom metric {metric_name} has no data in {days} days but costs $0.30/month",
                                'ARN': f"arn:aws:cloudwatch:{region}:{session.client('sts').get_caller_identity()['Account']}:metric/{namespace}/{metric['MetricName']}",
                                'Details': {
                                    'Namespace': namespace,
                                    'MetricName': metric['MetricName'],
                                    'Dimensions': metric.get('Dimensions', []),
                                    'EstimatedMonthlyCost': 0.30
                                }
                            })
                    except Exception:
                        continue
        except Exception as e:
            print(f"Error checking CloudWatch custom metrics in {region}: {e}")
        
        return results
    
    