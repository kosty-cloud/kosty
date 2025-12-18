import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any
from datetime import datetime, timedelta, timezone

class SnapshotsAuditService:
    service_name = "EBS Snapshots"
    
    cost_checks = [
        "check_old_snapshots"
    ]
    
    security_checks = []
    
    def cost_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run EBS Snapshots cost optimization audit"""
        results = []
        for check in self.cost_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def security_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run EBS Snapshots security audit"""
        results = []
        for check in self.security_checks:
            results.extend(getattr(self, check)(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run complete EBS Snapshots audit"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        return results
    
    def check_old_snapshots(self, session: boto3.Session, region: str, days: int = 30, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find EBS snapshots older than retention policy"""
        ec2 = session.client('ec2', region_name=region)
        results = []
        
        try:
            response = ec2.describe_snapshots(OwnerIds=['self'])
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            for snapshot in response['Snapshots']:
                if config_manager:
                    tags = get_resource_tags(snapshot, 'snapshot')
                    if should_exclude_resource_by_tags(tags, config_manager):
                        continue
                
                if snapshot['StartTime'] < cutoff_date:
                    results.append({
                        'AccountId': session.client('sts').get_caller_identity()['Account'],
                        'Region': region,
                        'region': region,
                        'Service': self.service_name,
                        'service': 'Snapshots',
                        'ResourceId': snapshot['SnapshotId'],
                        'ResourceName': snapshot['SnapshotId'],
                        'resource_id': snapshot['SnapshotId'],
                        'resource_name': snapshot['SnapshotId'],
                        'Issue': 'Old EBS snapshot',
                        'type': 'cost',
                        'check': 'old_snapshots',
                        'Risk': 'MEDIUM',
                        'severity': 'medium',
                        'size_gb': snapshot['VolumeSize'],
                        'volume_size_gb': snapshot['VolumeSize'],
                        'Description': f"EBS snapshot {snapshot['SnapshotId']} is older than {days} days",
                        'ARN': f"arn:aws:ec2:{region}:{session.client('sts').get_caller_identity()['Account']}:snapshot/{snapshot['SnapshotId']}",
                        'Details': {
                            'SnapshotId': snapshot['SnapshotId'],
                            'VolumeId': snapshot.get('VolumeId', 'N/A'),
                            'StartTime': snapshot['StartTime'].isoformat(),
                            'VolumeSize': snapshot['VolumeSize'],
                            'State': snapshot['State'],
                            'Description': snapshot.get('Description', 'N/A')
                        }
                    })
        except Exception as e:
            print(f"Error checking old snapshots in {region}: {e}")
        
        return results

class SnapshotsService:
    # Legacy method for backward compatibility
    def find_old_snapshots(self, session: boto3.Session, region: str, days: int = 30) -> List[Dict[str, Any]]:
        return SnapshotsAuditService().check_old_snapshots(session, region, days=days)