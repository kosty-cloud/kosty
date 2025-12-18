import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any
from datetime import datetime, timedelta

class APIGatewayAuditService:
    def __init__(self):
        self.service_name = "APIGateway"
        self.cost_checks = ['check_unused_apis']
        self.security_checks = []  # No security checks for API Gateway
    
    def cost_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all cost-related API Gateway audits"""
        results = []
        for check in self.cost_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def security_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all security-related API Gateway audits"""
        # No security checks for API Gateway
        return []
    
    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all API Gateway audits (cost + security)"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
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
                    # Check API request count
                    metrics = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ApiGateway',
                        MetricName='Count',
                        Dimensions=[
                            {'Name': 'ApiName', 'Value': api['name']}
                        ],
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
                            'ResourceArn': f"arn:aws:apigateway:{region}::/restapis/{api['id']}",
                            'Issue': f'API unused (0 requests {days} days)',
                            'type': 'cost',
                            'Risk': 'Waste $3.50/mo per API',
                            'severity': 'low',
                            'Details': {
                                'ApiId': api['id'],
                                'ApiName': api['name'],
                                'CreatedDate': api['createdDate'].isoformat(),
                                'Description': api.get('description', 'N/A'),
                                'EndpointConfiguration': api.get('endpointConfiguration', {}).get('types', [])
                            }
                        })
                except Exception:
                    continue
        except Exception as e:
            pass
        
        return results
    
   