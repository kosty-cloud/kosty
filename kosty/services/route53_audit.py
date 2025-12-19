import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any

class Route53AuditService:
    def __init__(self):
        self.service_name = "Route53"
        self.cost_checks = ['find_unused_hosted_zones']
        self.security_checks = []  # Route53 has no security checks

    def cost_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all cost-related Route53 audits"""
        results = []
        for check in self.cost_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results

    def security_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all security-related Route53 audits"""
        results = []
        for check in self.security_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results

    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all Route53 audits"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        return results

    def find_unused_hosted_zones(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find hosted zones with only NS/SOA records"""
        route53 = session.client('route53')
        results = []
        
        try:
            # Get all hosted zones
            paginator = route53.get_paginator('list_hosted_zones')
            
            for page in paginator.paginate():
                for zone in page['HostedZones']:
                    zone_id = zone['Id'].split('/')[-1]  # Extract ID from full path
                    
                    try:
                        # Get all records for this zone
                        records_paginator = route53.get_paginator('list_resource_record_sets')
                        record_types = set()
                        
                        for records_page in records_paginator.paginate(HostedZoneId=zone_id):
                            for record in records_page['ResourceRecordSets']:
                                record_types.add(record['Type'])
                        
                        # Check if zone only has NS and SOA records
                        if record_types.issubset({'NS', 'SOA'}):
                            results.append({
                                'AccountId': session.client('sts').get_caller_identity()['Account'],
                                'Region': 'global',  # Route53 is global
                                'Service': self.service_name,
                                'ResourceId': zone_id,
                                'ResourceArn': f"arn:aws:route53:::hostedzone/{zone_id}",
                                'Issue': 'Hosted zone with only NS/SOA records',
                                'type': 'cost',
                                'Risk': 'Waste $6/mo per zone',
                                'severity': 'low',
                                'Details': {
                                    'HostedZoneId': zone_id,
                                    'Name': zone['Name'],
                                    'RecordCount': zone.get('ResourceRecordSetCount', 0),
                                    'RecordTypes': list(record_types),
                                    'Private': zone.get('Config', {}).get('PrivateZone', False)
                                }
                            })
                    except Exception:
                        continue
        except Exception as e:
            pass
        
        return results

    # Individual check aliases
    def check_unused_hosted_zones(self, session: boto3.Session, region: str) -> List[Dict[str, Any]]:
        return self.find_unused_hosted_zones(session, region)