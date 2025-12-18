import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any
from datetime import datetime, timedelta

class DynamoDBAuditService:
    def __init__(self):
        self.service_name = "DynamoDB"
        self.cost_checks = ['find_idle_tables']
        self.security_checks = []  # No security checks for DynamoDB
    
    def cost_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all cost-related DynamoDB audits"""
        results = []
        for check in self.cost_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def security_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all security-related DynamoDB audits"""
        # No security checks for DynamoDB
        return []
    
    def audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all DynamoDB audits (cost + security)"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        return results
    
    def find_idle_tables(self, session: boto3.Session, region: str, days: int = 7, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find DynamoDB tables with no read/write activity"""
        dynamodb = session.client('dynamodb', region_name=region)
        cloudwatch = session.client('cloudwatch', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        results = []
        
        try:
            response = dynamodb.list_tables()
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            for table_name in response['TableNames']:
                try:
                    # Check read/write metrics
                    read_metrics = cloudwatch.get_metric_statistics(
                        Namespace='AWS/DynamoDB',
                        MetricName='ConsumedReadCapacityUnits',
                        Dimensions=[
                            {'Name': 'TableName', 'Value': table_name}
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Sum']
                    )
                    
                    write_metrics = cloudwatch.get_metric_statistics(
                        Namespace='AWS/DynamoDB',
                        MetricName='ConsumedWriteCapacityUnits',
                        Dimensions=[
                            {'Name': 'TableName', 'Value': table_name}
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Sum']
                    )
                    
                    total_reads = sum(dp['Sum'] for dp in read_metrics['Datapoints']) if read_metrics['Datapoints'] else 0
                    total_writes = sum(dp['Sum'] for dp in write_metrics['Datapoints']) if write_metrics['Datapoints'] else 0
                    
                    if total_reads == 0 and total_writes == 0:
                        # Get table details
                        table_detail = dynamodb.describe_table(TableName=table_name)
                        table = table_detail['Table']
                        
                        # Get provisioned capacity for cost calculation
                        provisioned_throughput = table.get('ProvisionedThroughput', {})
                        read_capacity = provisioned_throughput.get('ReadCapacityUnits', 0)
                        write_capacity = provisioned_throughput.get('WriteCapacityUnits', 0)
                        
                        results.append({
                            'AccountId': account_id,
                            'Region': region,
                            'region': region,
                            'Service': self.service_name,
                            'service': 'DynamoDB',
                            'ResourceId': table_name,
                            'ResourceName': table_name,
                            'ResourceArn': table['TableArn'],
                            'Issue': f'Table idle (0 reads/writes {days} days)',
                            'type': 'cost',
                            'Risk': 'Waste $5-50/mo per table',
                            'severity': 'medium',
                            'check': 'idle_tables',
                            'read_capacity_units': read_capacity,
                            'write_capacity_units': write_capacity,
                            'resource_id': table_name,
                            'resource_name': table_name,
                            'Details': {
                                'TableName': table_name,
                                'TableStatus': table['TableStatus'],
                                'CreationDateTime': table['CreationDateTime'].isoformat(),
                                'ItemCount': table['ItemCount'],
                                'TableSizeBytes': table['TableSizeBytes'],
                                'BillingMode': table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED'),
                                'ReadCapacityUnits': read_capacity,
                                'WriteCapacityUnits': write_capacity
                            }
                        })
                except Exception:
                    continue
        except Exception as e:
            pass
        
        return results
    
   