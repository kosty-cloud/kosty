import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any
from datetime import datetime, timedelta

class RDSAuditService:
    def __init__(self):
        self.cost_checks = ['find_idle_instances', 'find_oversized_instances', 'find_unused_read_replicas', 
                           'find_multi_az_non_prod', 'find_long_backup_retention', 'find_gp2_storage']
        self.security_checks = ['find_publicly_accessible', 'find_unencrypted_storage', 'find_default_username',
                               'find_wide_cidr_sg', 'find_disabled_backups', 'find_outdated_engine', 'find_no_ssl_enforcement']
    
    # Cost Audit Methods
    def find_idle_instances(self, session: boto3.Session, region: str, days: int = 7, cpu_threshold: int = 5, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find idle RDS instances (<5% CPU for 7 days)"""
        rds = session.client('rds', region_name=region)
        cloudwatch = session.client('cloudwatch', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        idle_instances = []
        
        try:
            instances = rds.describe_db_instances()
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            for instance in instances['DBInstances']:
                if instance['DBInstanceStatus'] != 'available':
                    continue
                    
                db_instance_id = instance['DBInstanceIdentifier']
                
                try:
                    metrics = cloudwatch.get_metric_statistics(
                        Namespace='AWS/RDS',
                        MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=['Average']
                    )
                    
                    if metrics['Datapoints']:
                        avg_cpu = sum(dp['Average'] for dp in metrics['Datapoints']) / len(metrics['Datapoints'])
                        if avg_cpu < cpu_threshold:
                            idle_instances.append({
                                'AccountId': account_id,
                                'DBInstanceIdentifier': db_instance_id,
                                'DBInstanceClass': instance['DBInstanceClass'],
                                'Engine': instance['Engine'],
                                'ARN': instance['DBInstanceArn'],
                                'Region': region,
                                'AvgCPU': round(avg_cpu, 2),
                                'Issue': f'Instance idle (<{cpu_threshold}% CPU for {days} days)',
                                'type': 'cost',
                                'Risk': 'Waste $100-1000/mo',
                                'severity': 'high',
                                'Service': 'RDS'
                            })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking idle RDS instances: {e}")
        
        return idle_instances
    
    def find_oversized_instances(self, session: boto3.Session, region: str, days: int = 14, cpu_threshold: int = 20, connection_threshold: int = 10, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find oversized RDS instances (<20% CPU and <10 connections)"""
        rds = session.client('rds', region_name=region)
        cloudwatch = session.client('cloudwatch', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        oversized_instances = []
        
        try:
            instances = rds.describe_db_instances()
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            for instance in instances['DBInstances']:
                if instance['DBInstanceStatus'] != 'available':
                    continue
                    
                db_instance_id = instance['DBInstanceIdentifier']
                
                try:
                    # Get CPU metrics
                    cpu_metrics = cloudwatch.get_metric_statistics(
                        Namespace='AWS/RDS',
                        MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=['Average']
                    )
                    
                    # Get connection metrics
                    conn_metrics = cloudwatch.get_metric_statistics(
                        Namespace='AWS/RDS',
                        MetricName='DatabaseConnections',
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=['Average']
                    )
                    
                    avg_cpu = 0
                    avg_connections = 0
                    
                    if cpu_metrics['Datapoints']:
                        avg_cpu = sum(dp['Average'] for dp in cpu_metrics['Datapoints']) / len(cpu_metrics['Datapoints'])
                    
                    if conn_metrics['Datapoints']:
                        avg_connections = sum(dp['Average'] for dp in conn_metrics['Datapoints']) / len(conn_metrics['Datapoints'])
                    
                    if avg_cpu < cpu_threshold and avg_connections < connection_threshold:
                        oversized_instances.append({
                            'AccountId': account_id,
                            'DBInstanceIdentifier': db_instance_id,
                            'DBInstanceClass': instance['DBInstanceClass'],
                            'Engine': instance['Engine'],
                            'ARN': instance['DBInstanceArn'],
                            'Region': region,
                            'region': region,
                            'AvgCPU': round(avg_cpu, 2),
                            'AvgConnections': round(avg_connections, 2),
                            'Issue': f'Oversized (<{cpu_threshold}% CPU and <{connection_threshold} connections)',
                            'type': 'cost',
                            'Risk': 'Waste 30-60%',
                            'severity': 'high',
                            'Service': 'RDS',
                            'service': 'RDS',
                            'check': 'oversized_instances',
                            'instance_class': instance['DBInstanceClass'],
                            'avg_cpu': round(avg_cpu, 2),
                            'resource_id': db_instance_id,
                            'resource_name': db_instance_id
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking oversized RDS instances: {e}")
        
        return oversized_instances
    
    def find_unused_read_replicas(self, session: boto3.Session, region: str, days: int = 7, read_threshold: int = 100, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find unused read replicas (<100 reads/day)"""
        rds = session.client('rds', region_name=region)
        cloudwatch = session.client('cloudwatch', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        unused_replicas = []
        
        try:
            instances = rds.describe_db_instances()
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            for instance in instances['DBInstances']:
                if not instance.get('ReadReplicaSourceDBInstanceIdentifier'):
                    continue  # Not a read replica
                    
                db_instance_id = instance['DBInstanceIdentifier']
                
                try:
                    metrics = cloudwatch.get_metric_statistics(
                        Namespace='AWS/RDS',
                        MetricName='ReadIOPS',
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,  # Daily
                        Statistics=['Sum']
                    )
                    
                    total_reads = 0
                    if metrics['Datapoints']:
                        total_reads = sum(dp['Sum'] for dp in metrics['Datapoints'])
                    
                    avg_reads_per_day = total_reads / days if days > 0 else 0
                    
                    if avg_reads_per_day < read_threshold:
                        unused_replicas.append({
                            'AccountId': account_id,
                            'DBInstanceIdentifier': db_instance_id,
                            'DBInstanceClass': instance['DBInstanceClass'],
                            'Engine': instance['Engine'],
                            'SourceDB': instance['ReadReplicaSourceDBInstanceIdentifier'],
                            'ARN': instance['DBInstanceArn'],
                            'Region': region,
                            'AvgReadsPerDay': round(avg_reads_per_day, 2),
                            'Issue': f'Unused read replica (<{read_threshold} reads/day)',
                            'type': 'cost',
                            'Risk': 'Waste $100-500/mo',
                            'severity': 'high',
                            'Service': 'RDS'
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking unused read replicas: {e}")
        
        return unused_replicas
    
    def find_multi_az_non_prod(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find Multi-AZ for non-production environments"""
        rds = session.client('rds', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        multi_az_non_prod = []
        
        try:
            instances = rds.describe_db_instances()
            
            for instance in instances['DBInstances']:
                if not instance.get('MultiAZ', False):
                    continue
                    
                # Check if it's likely non-production based on naming or tags
                db_instance_id = instance['DBInstanceIdentifier'].lower()
                is_non_prod = any(keyword in db_instance_id for keyword in ['dev', 'test', 'staging', 'demo', 'sandbox'])
                
                if is_non_prod:
                    multi_az_non_prod.append({
                        'AccountId': account_id,
                        'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                        'DBInstanceClass': instance['DBInstanceClass'],
                        'Engine': instance['Engine'],
                        'ARN': instance['DBInstanceArn'],
                        'Region': region,
                        'MultiAZ': instance['MultiAZ'],
                        'Issue': 'Multi-AZ for non-production',
                        'type': 'cost',
                        'Risk': 'Waste 100% (double cost)',
                        'severity': 'medium',
                        'Service': 'RDS'
                    })
        except Exception as e:
            print(f"Error checking Multi-AZ non-prod: {e}")
        
        return multi_az_non_prod
    
    def find_long_backup_retention(self, session: boto3.Session, region: str, retention_threshold: int = 7, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find backup retention >7 days for dev/test"""
        rds = session.client('rds', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        long_retention = []
        
        try:
            instances = rds.describe_db_instances()
            
            for instance in instances['DBInstances']:
                backup_retention = instance.get('BackupRetentionPeriod', 0)
                if backup_retention <= retention_threshold:
                    continue
                    
                # Check if it's likely dev/test
                db_instance_id = instance['DBInstanceIdentifier'].lower()
                is_dev_test = any(keyword in db_instance_id for keyword in ['dev', 'test', 'staging', 'demo', 'sandbox'])
                
                if is_dev_test:
                    long_retention.append({
                        'AccountId': account_id,
                        'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                        'DBInstanceClass': instance['DBInstanceClass'],
                        'Engine': instance['Engine'],
                        'ARN': instance['DBInstanceArn'],
                        'Region': region,
                        'BackupRetentionPeriod': backup_retention,
                        'Issue': f'Backup retention >{retention_threshold} days for dev/test',
                        'type': 'cost',
                        'Risk': 'Waste backup storage',
                        'severity': 'low',
                        'Service': 'RDS'
                    })
        except Exception as e:
            print(f"Error checking backup retention: {e}")
        
        return long_retention
    
    def find_gp2_storage(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find gp2 storage (not gp3)"""
        rds = session.client('rds', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        gp2_storage = []
        
        try:
            instances = rds.describe_db_instances()
            
            for instance in instances['DBInstances']:
                storage_type = instance.get('StorageType', '')
                if storage_type == 'gp2':
                    gp2_storage.append({
                        'AccountId': account_id,
                        'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                        'DBInstanceClass': instance['DBInstanceClass'],
                        'Engine': instance['Engine'],
                        'StorageType': storage_type,
                        'AllocatedStorage': instance.get('AllocatedStorage', 0),
                        'ARN': instance['DBInstanceArn'],
                        'Region': region,
                        'Issue': 'gp2 storage (not gp3)',
                        'type': 'cost',
                        'Risk': 'Waste 20% storage cost',
                        'severity': 'medium',
                        'Service': 'RDS'
                    })
        except Exception as e:
            print(f"Error checking gp2 storage: {e}")
        
        return gp2_storage
    
    # Security Audit Methods
    def find_publicly_accessible(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find publicly accessible databases"""
        rds = session.client('rds', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        public_instances = []
        
        try:
            instances = rds.describe_db_instances()
            
            for instance in instances['DBInstances']:
                if instance.get('PubliclyAccessible', False):
                    public_instances.append({
                        'AccountId': account_id,
                        'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                        'DBInstanceClass': instance['DBInstanceClass'],
                        'Engine': instance['Engine'],
                        'ARN': instance['DBInstanceArn'],
                        'Region': region,
                        'PubliclyAccessible': instance['PubliclyAccessible'],
                        'Issue': 'Publicly accessible database',
                        'type': 'security',
                        'Risk': 'Direct internet DB access',
                        'severity': 'critical',
                        'Service': 'RDS'
                    })
        except Exception as e:
            print(f"Error checking publicly accessible databases: {e}")
        
        return public_instances
    
    def find_unencrypted_storage(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find storage not encrypted"""
        rds = session.client('rds', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        unencrypted_instances = []
        
        try:
            instances = rds.describe_db_instances()
            
            for instance in instances['DBInstances']:
                if not instance.get('StorageEncrypted', False):
                    unencrypted_instances.append({
                        'AccountId': account_id,
                        'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                        'DBInstanceClass': instance['DBInstanceClass'],
                        'Engine': instance['Engine'],
                        'ARN': instance['DBInstanceArn'],
                        'Region': region,
                        'StorageEncrypted': instance.get('StorageEncrypted', False),
                        'Issue': 'Storage not encrypted',
                        'type': 'security',
                        'Risk': 'Data breach if storage compromised',
                        'severity': 'critical',
                        'Service': 'RDS'
                    })
        except Exception as e:
            print(f"Error checking unencrypted storage: {e}")
        
        return unencrypted_instances
    
    def find_default_username(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find master username is default"""
        rds = session.client('rds', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        default_username = []
        
        default_usernames = ['admin', 'root', 'postgres', 'mysql', 'sa', 'master']
        
        try:
            instances = rds.describe_db_instances()
            
            for instance in instances['DBInstances']:
                master_username = instance.get('MasterUsername', '').lower()
                if master_username in default_usernames:
                    default_username.append({
                        'AccountId': account_id,
                        'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                        'DBInstanceClass': instance['DBInstanceClass'],
                        'Engine': instance['Engine'],
                        'MasterUsername': instance.get('MasterUsername', ''),
                        'ARN': instance['DBInstanceArn'],
                        'Region': region,
                        'Issue': 'Master username is default (admin/root/postgres)',
                        'type': 'security',
                        'Risk': 'First brute force target',
                        'severity': 'high',
                        'Service': 'RDS'
                    })
        except Exception as e:
            print(f"Error checking default usernames: {e}")
        
        return default_username
    
    def find_wide_cidr_sg(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find security group allows wide CIDR (>=/16)"""
        rds = session.client('rds', region_name=region)
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        wide_cidr_instances = []
        
        try:
            instances = rds.describe_db_instances()
            
            for instance in instances['DBInstances']:
                vpc_security_groups = instance.get('VpcSecurityGroups', [])
                
                for sg in vpc_security_groups:
                    sg_id = sg['VpcSecurityGroupId']
                    try:
                        sg_details = ec2.describe_security_groups(GroupIds=[sg_id])
                        for sg_detail in sg_details['SecurityGroups']:
                            for rule in sg_detail.get('IpPermissions', []):
                                for ip_range in rule.get('IpRanges', []):
                                    cidr = ip_range.get('CidrIp', '')
                                    if '/' in cidr:
                                        prefix = int(cidr.split('/')[1])
                                        if prefix <= 16:
                                            wide_cidr_instances.append({
                                                'AccountId': account_id,
                                                'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                                                'DBInstanceClass': instance['DBInstanceClass'],
                                                'Engine': instance['Engine'],
                                                'SecurityGroupId': sg_id,
                                                'CIDR': cidr,
                                                'ARN': instance['DBInstanceArn'],
                                                'Region': region,
                                                'Issue': 'Security group allows wide CIDR (>=/16)',
                                                'type': 'security',
                                                'Risk': 'Overly permissive network access',
                                                'severity': 'high',
                                                'Service': 'RDS'
                                            })
                                            break
                    except Exception:
                        continue
        except Exception as e:
            print(f"Error checking wide CIDR security groups: {e}")
        
        return wide_cidr_instances
    
    def find_disabled_backups(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find automated backups disabled (retention=0)"""
        rds = session.client('rds', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        disabled_backups = []
        
        try:
            instances = rds.describe_db_instances()
            
            for instance in instances['DBInstances']:
                backup_retention = instance.get('BackupRetentionPeriod', 0)
                if backup_retention == 0:
                    disabled_backups.append({
                        'AccountId': account_id,
                        'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                        'DBInstanceClass': instance['DBInstanceClass'],
                        'Engine': instance['Engine'],
                        'BackupRetentionPeriod': backup_retention,
                        'ARN': instance['DBInstanceArn'],
                        'Region': region,
                        'Issue': 'Automated backups disabled (retention=0)',
                        'type': 'security',
                        'Risk': 'Data loss - no recovery',
                        'severity': 'high',
                        'Service': 'RDS'
                    })
        except Exception as e:
            print(f"Error checking disabled backups: {e}")
        
        return disabled_backups
    
    def find_outdated_engine(self, session: boto3.Session, region: str, months_threshold: int = 12, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find engine version outdated (>12 months)"""
        # This is a simplified check - in reality, you'd need to maintain a database of engine versions and their release dates
        rds = session.client('rds', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        outdated_engines = []
        
        # Simplified check for obviously old versions
        old_versions = {
            'mysql': ['5.6', '5.7.0', '5.7.1', '5.7.2'],
            'postgres': ['9.', '10.', '11.0', '11.1'],
            'oracle': ['11.', '12.1'],
            'sqlserver': ['2012', '2014', '2016']
        }
        
        try:
            instances = rds.describe_db_instances()
            
            for instance in instances['DBInstances']:
                engine = instance.get('Engine', '').lower()
                engine_version = instance.get('EngineVersion', '')
                
                is_outdated = False
                for engine_type, versions in old_versions.items():
                    if engine_type in engine:
                        for old_version in versions:
                            if engine_version.startswith(old_version):
                                is_outdated = True
                                break
                        break
                
                if is_outdated:
                    outdated_engines.append({
                        'AccountId': account_id,
                        'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                        'DBInstanceClass': instance['DBInstanceClass'],
                        'Engine': instance['Engine'],
                        'EngineVersion': engine_version,
                        'ARN': instance['DBInstanceArn'],
                        'Region': region,
                        'Issue': f'Engine version outdated (>{months_threshold} months)',
                        'type': 'security',
                        'Risk': 'Known CVEs unpatched',
                        'severity': 'medium',
                        'Service': 'RDS'
                    })
        except Exception as e:
            print(f"Error checking outdated engines: {e}")
        
        return outdated_engines
    
    def find_no_ssl_enforcement(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find no SSL/TLS enforcement"""
        rds = session.client('rds', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        no_ssl_instances = []
        
        try:
            instances = rds.describe_db_instances()
            
            for instance in instances['DBInstances']:
                # Check parameter groups for SSL enforcement
                db_parameter_groups = instance.get('DBParameterGroups', [])
                
                # This is a simplified check - in reality, you'd need to check the actual parameter values
                # For now, we'll flag instances that might not have SSL enforcement
                no_ssl_instances.append({
                    'AccountId': account_id,
                    'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                    'DBInstanceClass': instance['DBInstanceClass'],
                    'Engine': instance['Engine'],
                    'ParameterGroups': [pg['DBParameterGroupName'] for pg in db_parameter_groups],
                    'ARN': instance['DBInstanceArn'],
                    'Region': region,
                    'Issue': 'No SSL/TLS enforcement',
                    'type': 'security',
                    'Risk': 'Man-in-the-middle attacks',
                    'severity': 'medium',
                    'Service': 'RDS'
                })
        except Exception as e:
            print(f"Error checking SSL enforcement: {e}")
        
        return no_ssl_instances
    
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
    
    # Individual Check Method Aliases
    def check_idle_instances(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_idle_instances(session, region, **kwargs)
    
    def check_oversized_instances(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_oversized_instances(session, region, **kwargs)
    
    def check_unused_read_replicas(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_unused_read_replicas(session, region, **kwargs)
    
    def check_multi_az_non_prod(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_multi_az_non_prod(session, region, **kwargs)
    
    def check_long_backup_retention(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_long_backup_retention(session, region, **kwargs)
    
    def check_gp2_storage(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_gp2_storage(session, region, **kwargs)
    
    def check_publicly_accessible(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_publicly_accessible(session, region, **kwargs)
    
    def check_unencrypted_storage(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_unencrypted_storage(session, region, **kwargs)
    
    def check_default_username(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_default_username(session, region, **kwargs)
    
    def check_wide_cidr_sg(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_wide_cidr_sg(session, region, **kwargs)
    
    def check_disabled_backups(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_disabled_backups(session, region, **kwargs)
    
    def check_outdated_engine(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_outdated_engine(session, region, **kwargs)
    
    def check_no_ssl_enforcement(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_no_ssl_enforcement(session, region, **kwargs)