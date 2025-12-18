import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any
from datetime import datetime, timedelta

class EBSAuditService:
    def __init__(self):
        self.cost_checks = ['find_orphan_volumes', 'find_low_io_volumes', 'find_old_snapshots', 'find_gp2_volumes']
        self.security_checks = ['find_unencrypted_orphan', 'find_unencrypted_in_use', 'find_public_snapshots', 'find_no_recent_snapshot']
    
    def _get_volume_name(self, volume):
        """Extract volume name from tags or return volume ID"""
        tags = volume.get('Tags', [])
        for tag in tags:
            if tag['Key'] == 'Name':
                return tag['Value']
        return volume['VolumeId']
    
    # Audit Methods
    def cost_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all cost-related audits"""
        results = []
        for check in self.cost_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def security_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all security-related audits"""
        results = []
        for check in self.security_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all audits (cost + security)"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        return results
    
    
    # Cost Audit Methods
    def find_orphan_volumes(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find volumes in available state (detached)"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        orphan_volumes = []
        
        try:
            volumes = ec2.describe_volumes(
                Filters=[{'Name': 'status', 'Values': ['available']}]
            )
            
            for volume in volumes['Volumes']:
                volume_name = self._get_volume_name(volume)
                orphan_volumes.append({
                    'AccountId': account_id,
                    'VolumeId': volume['VolumeId'],
                    'Name': volume_name,
                    'VolumeType': volume['VolumeType'],
                    'Size': volume['Size'],
                    'ARN': f"arn:aws:ec2:{region}:{account_id}:volume/{volume['VolumeId']}",
                    'Region': region,
                    'region': region,
                    'CreateTime': volume['CreateTime'].isoformat(),
                    'Issue': f'Volume "{volume_name}" in available state (detached)',
                    'type': 'cost',
                    'Risk': 'Waste $10-100/mo per volume',
                    'severity': 'high',
                    'Service': 'EBS',
                    'service': 'EBS',
                    'check': 'orphan_volumes',
                    'size_gb': volume['Size'],
                    'volume_type': volume['VolumeType'].lower(),
                    'resource_id': volume['VolumeId'],
                    'resource_name': volume_name
                })
        except Exception as e:
            print(f"Error checking orphan volumes: {e}")
        
        return orphan_volumes
    
    def find_low_io_volumes(self, session: boto3.Session, region: str, iops_threshold: int = 10, days: int = 7, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find volumes with low I/O (<X IOPS/GB)"""
        ec2 = session.client('ec2', region_name=region)
        cloudwatch = session.client('cloudwatch', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        low_io_volumes = []
        
        try:
            volumes = ec2.describe_volumes(
                Filters=[{'Name': 'status', 'Values': ['in-use']}]
            )
            
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            for volume in volumes['Volumes']:
                volume_id = volume['VolumeId']
                volume_size = volume['Size']
                
                try:
                    # Get IOPS metrics
                    read_ops = cloudwatch.get_metric_statistics(
                        Namespace='AWS/EBS',
                        MetricName='VolumeReadOps',
                        Dimensions=[{'Name': 'VolumeId', 'Value': volume_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=['Sum']
                    )
                    
                    write_ops = cloudwatch.get_metric_statistics(
                        Namespace='AWS/EBS',
                        MetricName='VolumeWriteOps',
                        Dimensions=[{'Name': 'VolumeId', 'Value': volume_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=['Sum']
                    )
                    
                    total_ops = 0
                    if read_ops['Datapoints']:
                        total_ops += sum(dp['Sum'] for dp in read_ops['Datapoints'])
                    if write_ops['Datapoints']:
                        total_ops += sum(dp['Sum'] for dp in write_ops['Datapoints'])
                    
                    # Calculate IOPS per GB
                    hours = days * 24
                    avg_iops_per_hour = total_ops / hours if hours > 0 else 0
                    iops_per_gb = avg_iops_per_hour / volume_size if volume_size > 0 else 0
                    
                    if iops_per_gb < iops_threshold:
                        low_io_volumes.append({
                            'AccountId': account_id,
                            'VolumeId': volume_id,
                            'VolumeType': volume['VolumeType'],
                            'Size': volume_size,
                            'ARN': f"arn:aws:ec2:{region}:{account_id}:volume/{volume_id}",
                            'Region': region,
                            'IOPSPerGB': round(iops_per_gb, 2),
                            'Issue': f'Volume with low I/O (<{iops_threshold} IOPS/GB)',
                            'type': 'cost',
                            'Risk': 'Oversized - can downsize',
                            'severity': 'medium',
                            'Service': 'EBS'
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking low I/O volumes: {e}")
        
        return low_io_volumes
    
    def find_old_snapshots(self, session: boto3.Session, region: str, days: int = 90, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find snapshots older than X days"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        old_snapshots = []
        
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            snapshots = ec2.describe_snapshots(OwnerIds=[account_id])
            
            for snapshot in snapshots['Snapshots']:
                start_time = snapshot['StartTime'].replace(tzinfo=None)
                if start_time < cutoff_date:
                    old_snapshots.append({
                        'AccountId': account_id,
                        'SnapshotId': snapshot['SnapshotId'],
                        'VolumeId': snapshot.get('VolumeId', 'N/A'),
                        'VolumeSize': snapshot['VolumeSize'],
                        'ARN': f"arn:aws:ec2:{region}:{account_id}:snapshot/{snapshot['SnapshotId']}",
                        'Region': region,
                        'region': region,
                        'StartTime': snapshot['StartTime'].isoformat(),
                        'Age': (datetime.now() - start_time).days,
                        'Issue': f'Snapshot older than {days} days',
                        'type': 'cost',
                        'Risk': 'Waste $5-50/mo per snapshot',
                        'severity': 'low',
                        'Service': 'EBS',
                        'service': 'EBS',
                        'check': 'old_snapshots',
                        'size_gb': snapshot['VolumeSize'],
                        'volume_size_gb': snapshot['VolumeSize'],
                        'resource_id': snapshot['SnapshotId'],
                        'resource_name': snapshot['SnapshotId']
                    })
        except Exception as e:
            print(f"Error checking old snapshots: {e}")
        
        return old_snapshots
    
    def find_gp2_volumes(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find gp2 volumes (not gp3)"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        gp2_volumes = []
        
        try:
            volumes = ec2.describe_volumes(
                Filters=[{'Name': 'volume-type', 'Values': ['gp2']}]
            )
            
            for volume in volumes['Volumes']:
                gp2_volumes.append({
                    'AccountId': account_id,
                    'VolumeId': volume['VolumeId'],
                    'VolumeType': volume['VolumeType'],
                    'Size': volume['Size'],
                    'ARN': f"arn:aws:ec2:{region}:{account_id}:volume/{volume['VolumeId']}",
                    'Region': region,
                    'State': volume['State'],
                    'Issue': 'gp2 volumes (not gp3)',
                    'type': 'cost',
                    'Risk': 'Waste 20% vs gp3',
                    'severity': 'medium',
                    'Service': 'EBS'
                })
        except Exception as e:
            print(f"Error checking gp2 volumes: {e}")
        
        return gp2_volumes
    
    # Security Audit Methods
    def find_unencrypted_orphan(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find unencrypted orphaned volumes"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        unencrypted_orphan = []
        
        try:
            volumes = ec2.describe_volumes(
                Filters=[
                    {'Name': 'status', 'Values': ['available']},
                    {'Name': 'encrypted', 'Values': ['false']}
                ]
            )
            
            for volume in volumes['Volumes']:
                unencrypted_orphan.append({
                    'AccountId': account_id,
                    'VolumeId': volume['VolumeId'],
                    'VolumeType': volume['VolumeType'],
                    'Size': volume['Size'],
                    'ARN': f"arn:aws:ec2:{region}:{account_id}:volume/{volume['VolumeId']}",
                    'Region': region,
                    'Encrypted': volume['Encrypted'],
                    'Issue': 'Unencrypted orphaned volume',
                    'type': 'security',
                    'Risk': 'Data remnants accessible',
                    'severity': 'critical',
                    'Service': 'EBS'
                })
        except Exception as e:
            print(f"Error checking unencrypted orphan volumes: {e}")
        
        return unencrypted_orphan
    
    def find_unencrypted_in_use(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find unencrypted volumes in use"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        unencrypted_in_use = []
        
        try:
            volumes = ec2.describe_volumes(
                Filters=[
                    {'Name': 'status', 'Values': ['in-use']},
                    {'Name': 'encrypted', 'Values': ['false']}
                ]
            )
            
            for volume in volumes['Volumes']:
                instance_id = volume['Attachments'][0]['InstanceId'] if volume['Attachments'] else 'N/A'
                unencrypted_in_use.append({
                    'AccountId': account_id,
                    'VolumeId': volume['VolumeId'],
                    'VolumeType': volume['VolumeType'],
                    'Size': volume['Size'],
                    'InstanceId': instance_id,
                    'ARN': f"arn:aws:ec2:{region}:{account_id}:volume/{volume['VolumeId']}",
                    'Region': region,
                    'Encrypted': volume['Encrypted'],
                    'Issue': 'Unencrypted volume in use',
                    'type': 'security',
                    'Risk': 'Data at rest not protected',
                    'severity': 'high',
                    'Service': 'EBS'
                })
        except Exception as e:
            print(f"Error checking unencrypted in-use volumes: {e}")
        
        return unencrypted_in_use
    
    def find_public_snapshots(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find public snapshots"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        public_snapshots = []
        
        try:
            snapshots = ec2.describe_snapshots(OwnerIds=[account_id])
            
            for snapshot in snapshots['Snapshots']:
                try:
                    # Check if snapshot is public
                    attrs = ec2.describe_snapshot_attribute(
                        SnapshotId=snapshot['SnapshotId'],
                        Attribute='createVolumePermission'
                    )
                    
                    for perm in attrs.get('CreateVolumePermissions', []):
                        if perm.get('Group') == 'all':
                            public_snapshots.append({
                                'AccountId': account_id,
                                'SnapshotId': snapshot['SnapshotId'],
                                'VolumeId': snapshot.get('VolumeId', 'N/A'),
                                'VolumeSize': snapshot['VolumeSize'],
                                'ARN': f"arn:aws:ec2:{region}:{account_id}:snapshot/{snapshot['SnapshotId']}",
                                'Region': region,
                                'StartTime': snapshot['StartTime'].isoformat(),
                                'Issue': 'Public snapshot exists',
                                'type': 'security',
                                'Risk': 'Anyone can copy volume data',
                                'severity': 'critical',
                                'Service': 'EBS'
                            })
                            break
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking public snapshots: {e}")
        
        return public_snapshots
    
    def find_no_recent_snapshot(self, session: boto3.Session, region: str, days: int = 7, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find volumes with no recent snapshot"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        no_recent_snapshot = []
        
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            volumes = ec2.describe_volumes(
                Filters=[{'Name': 'status', 'Values': ['in-use']}]
            )
            
            for volume in volumes['Volumes']:
                volume_id = volume['VolumeId']
                
                # Check for recent snapshots
                snapshots = ec2.describe_snapshots(
                    OwnerIds=[account_id],
                    Filters=[{'Name': 'volume-id', 'Values': [volume_id]}]
                )
                
                has_recent_snapshot = False
                for snapshot in snapshots['Snapshots']:
                    start_time = snapshot['StartTime'].replace(tzinfo=None)
                    if start_time > cutoff_date:
                        has_recent_snapshot = True
                        break
                
                if not has_recent_snapshot:
                    no_recent_snapshot.append({
                        'AccountId': account_id,
                        'VolumeId': volume_id,
                        'VolumeType': volume['VolumeType'],
                        'Size': volume['Size'],
                        'ARN': f"arn:aws:ec2:{region}:{account_id}:volume/{volume_id}",
                        'Region': region,
                        'Issue': f'No recent snapshot ({days}+ days)',
                        'type': 'security',
                        'Risk': 'No backup - data loss risk',
                        'severity': 'medium',
                        'Service': 'EBS'
                    })
        except Exception as e:
            print(f"Error checking recent snapshots: {e}")
        
        return no_recent_snapshot
    
    
    # Individual Check Method Aliases (for CLI compatibility)
    def check_orphan_volumes(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_orphan_volumes(session, region, **kwargs)
    
    def check_low_io_volumes(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_low_io_volumes(session, region, **kwargs)
    
    def check_old_snapshots(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_old_snapshots(session, region, **kwargs)
    
    def check_gp2_volumes(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_gp2_volumes(session, region, **kwargs)
    
    def check_unencrypted_orphan(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_unencrypted_orphan(session, region, **kwargs)
    
    def check_unencrypted_in_use(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_unencrypted_in_use(session, region, **kwargs)
    
    def check_public_snapshots(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_public_snapshots(session, region, **kwargs)
    
    def check_no_recent_snapshot(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_no_recent_snapshot(session, region, **kwargs)