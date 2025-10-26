import boto3
from typing import List, Dict, Any
from datetime import datetime, timedelta, timezone

class SnapshotsAuditService:
    service_name = "EBS Snapshots"
    
    cost_checks = [
        "check_old_snapshots"
    ]
    
    security_checks = []
    
    def cost_audit(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        """Run EBS Snapshots cost optimization audit"""
        results = []
        for check in self.cost_checks:
            results.extend(getattr(self, check)(session, region, **kwargs))
        return results
    
    def security_audit(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        """Run EBS Snapshots security audit"""
        results = []
        for check in self.security_checks:
            results.extend(getattr(self, check)(session, region, **kwargs))
        return results
    
    def audit(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        """Run complete EBS Snapshots audit"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        return results
    
    def check_old_snapshots(self, session: boto3.Session, region: str, days: int = 30, **kwargs) -> List[Dict[str, Any]]:
        """Find EBS snapshots older than retention policy"""
        ec2 = session.client('ec2', region_name=region)
        results = []
        
        try:
            response = ec2.describe_snapshots(OwnerIds=['self'])
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            for snapshot in response['Snapshots']:
                if snapshot['StartTime'] < cutoff_date:
                    results.append({
                        'AccountId': session.client('sts').get_caller_identity()['Account'],
                        'Region': region,
                        'Service': self.service_name,
                        'ResourceId': snapshot['SnapshotId'],
                        'ResourceName': snapshot['SnapshotId'],
                        'Issue': 'Old EBS snapshot',
                        'type': 'cost',
                        'Risk': 'MEDIUM',
                        'severity': 'medium',
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