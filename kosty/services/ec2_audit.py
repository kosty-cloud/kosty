import boto3
from typing import List, Dict, Any
from datetime import datetime, timedelta
import json
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags

class EC2AuditService:
    def __init__(self):
        self.cost_checks = ['find_stopped', 'find_idle', 'find_oversized', 'find_previous_generation']
        self.security_checks = ['find_ssh_open', 'find_rdp_open', 'find_database_ports_open', 
                               'find_public_non_web', 'find_old_ami', 'find_imdsv1', 
                               'find_unencrypted_ebs', 'find_no_recent_backup']
    
    # Cost Audit Methods
    def find_stopped(self, session: boto3.Session, region: str, days: int = 7, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find instances stopped for X+ days"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        stopped_instances = []
        
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            instances = ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}]
            )
            
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if config_manager:
                        tags = get_resource_tags(instance, 'ec2')
                        if should_exclude_resource_by_tags(tags, config_manager):
                            continue
                    
                    state_transition_time = instance.get('StateTransitionReason', '')
                    if state_transition_time:
                        try:
                            # Parse state transition time
                            import re
                            match = re.search(r'\((.*?)\)', state_transition_time)
                            if match:
                                transition_str = match.group(1)
                                transition_time = datetime.strptime(transition_str, '%Y-%m-%d %H:%M:%S %Z')
                                if transition_time < cutoff_date:
                                    stopped_instances.append({
                                        'AccountId': account_id,
                                        'InstanceId': instance['InstanceId'],
                                        'InstanceType': instance['InstanceType'],
                                        'ARN': f"arn:aws:ec2:{region}:{account_id}:instance/{instance['InstanceId']}",
                                        'Region': region,
                                        'region': region,
                                        'StoppedDays': (datetime.now() - transition_time).days,
                                        'Issue': f'Instance stopped for {days}+ days',
                                        'type': 'cost',
                                        'Risk': 'Waste $30-500/mo per instance',
                                        'severity': 'high',
                                        'Service': 'EC2',
                                        'service': 'EC2',
                                        'check': 'stopped_instances',
                                        'instance_type': instance['InstanceType'],
                                        'resource_id': instance['InstanceId'],
                                        'resource_name': instance['InstanceId']
                                    })
                        except:
                            continue
        except Exception as e:
            print(f"Error checking stopped instances: {e}")
        
        return stopped_instances
    
    def find_idle(self, session: boto3.Session, region: str, days: int = 7, cpu_threshold: int = 5, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find idle instances (<X% CPU for Y days)"""
        ec2 = session.client('ec2', region_name=region)
        cloudwatch = session.client('cloudwatch', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        idle_instances = []
        
        try:
            instances = ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if config_manager:
                        tags = get_resource_tags(instance, 'ec2')
                        if should_exclude_resource_by_tags(tags, config_manager):
                            continue
                    
                    instance_id = instance['InstanceId']
                    
                    try:
                        # Get CPU utilization
                        metrics = cloudwatch.get_metric_statistics(
                            Namespace='AWS/EC2',
                            MetricName='CPUUtilization',
                            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
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
                                    'InstanceId': instance_id,
                                    'InstanceType': instance['InstanceType'],
                                    'ARN': f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
                                    'Region': region,
                                    'region': region,
                                    'AvgCPU': round(avg_cpu, 2),
                                    'Issue': f'Instance idle (<{cpu_threshold}% CPU for {days} days)',
                                    'type': 'cost',
                                    'Risk': 'Waste 80-95% of instance cost',
                                    'severity': 'high',
                                    'Service': 'EC2',
                                    'service': 'EC2',
                                    'check': 'idle_instances',
                                    'instance_type': instance['InstanceType'],
                                    'resource_id': instance_id,
                                    'resource_name': instance_id
                                })
                    except Exception:
                        continue
        except Exception as e:
            print(f"Error checking idle instances: {e}")
        
        return idle_instances
    
    def find_oversized(self, session: boto3.Session, region: str, cpu_threshold: int = 20, days: int = 14, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find oversized instances (<X% CPU)"""
        ec2 = session.client('ec2', region_name=region)
        cloudwatch = session.client('cloudwatch', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        oversized_instances = []
        
        try:
            instances = ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if config_manager:
                        tags = get_resource_tags(instance, 'ec2')
                        if should_exclude_resource_by_tags(tags, config_manager):
                            continue
                    
                    instance_id = instance['InstanceId']
                    
                    try:
                        metrics = cloudwatch.get_metric_statistics(
                            Namespace='AWS/EC2',
                            MetricName='CPUUtilization',
                            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=3600,
                            Statistics=['Average']
                        )
                        
                        if metrics['Datapoints']:
                            avg_cpu = sum(dp['Average'] for dp in metrics['Datapoints']) / len(metrics['Datapoints'])
                            if avg_cpu < cpu_threshold:
                                oversized_instances.append({
                                    'AccountId': account_id,
                                    'InstanceId': instance_id,
                                    'InstanceType': instance['InstanceType'],
                                    'ARN': f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
                                    'Region': region,
                                    'region': region,
                                    'AvgCPU': round(avg_cpu, 2),
                                    'Issue': f'Oversized instance (<{cpu_threshold}% CPU)',
                                    'type': 'cost',
                                    'Risk': 'Waste 30-60% per instance',
                                    'severity': 'high',
                                    'Service': 'EC2',
                                    'service': 'EC2',
                                    'check': 'oversized_instances',
                                    'instance_type': instance['InstanceType'],
                                    'resource_id': instance_id,
                                    'resource_name': instance_id
                                })
                    except Exception:
                        continue
        except Exception as e:
            print(f"Error checking oversized instances: {e}")
        
        return oversized_instances
    
    def find_previous_generation(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find previous generation instance types"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        old_generation = []
        
        previous_gen_types = ['t2', 'm4', 'c4', 'r4', 'm3', 'c3', 'r3', 't1', 'm1', 'c1']
        
        try:
            instances = ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]
            )
            
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if config_manager:
                        tags = get_resource_tags(instance, 'ec2')
                        if should_exclude_resource_by_tags(tags, config_manager):
                            continue
                    
                    instance_type = instance['InstanceType']
                    instance_family = instance_type.split('.')[0]
                    
                    if instance_family in previous_gen_types:
                        old_generation.append({
                            'AccountId': account_id,
                            'InstanceId': instance['InstanceId'],
                            'InstanceType': instance_type,
                            'ARN': f"arn:aws:ec2:{region}:{account_id}:instance/{instance['InstanceId']}",
                            'Region': region,
                            'Issue': 'Instance type previous generation (t2/m4/c4)',
                            'type': 'cost',
                            'Risk': 'Waste 10-20% vs current gen',
                            'severity': 'medium',
                            'Service': 'EC2'
                        })
        except Exception as e:
            print(f"Error checking previous generation instances: {e}")
        
        return old_generation
    
    # Security Audit Methods
    def find_ssh_open(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find instances with SSH port 22 open to 0.0.0.0/0"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        ssh_open_instances = []
        
        try:
            # Get security groups with SSH open
            security_groups = ec2.describe_security_groups()
            ssh_open_sgs = []
            
            for sg in security_groups['SecurityGroups']:
                for rule in sg.get('IpPermissions', []):
                    if (rule.get('FromPort') == 22 and rule.get('ToPort') == 22 and 
                        any(ip_range.get('CidrIp') == '0.0.0.0/0' for ip_range in rule.get('IpRanges', []))):
                        ssh_open_sgs.append(sg['GroupId'])
            
            # Find instances using these security groups
            instances = ec2.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if config_manager:
                        tags = get_resource_tags(instance, 'ec2')
                        if should_exclude_resource_by_tags(tags, config_manager):
                            continue
                    
                    instance_sgs = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    if any(sg_id in ssh_open_sgs for sg_id in instance_sgs):
                        ssh_open_instances.append({
                            'AccountId': account_id,
                            'InstanceId': instance['InstanceId'],
                            'InstanceType': instance['InstanceType'],
                            'ARN': f"arn:aws:ec2:{region}:{account_id}:instance/{instance['InstanceId']}",
                            'Region': region,
                            'SecurityGroups': instance_sgs,
                            'Issue': 'SSH port 22 open to 0.0.0.0/0',
                            'type': 'security',
                            'Risk': 'Brute force attacks (38k/day avg)',
                            'severity': 'critical',
                            'Service': 'EC2'
                        })
        except Exception as e:
            print(f"Error checking SSH open instances: {e}")
        
        return ssh_open_instances
    
    def find_rdp_open(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find instances with RDP port 3389 open to 0.0.0.0/0"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        rdp_open_instances = []
        
        try:
            security_groups = ec2.describe_security_groups()
            rdp_open_sgs = []
            
            for sg in security_groups['SecurityGroups']:
                for rule in sg.get('IpPermissions', []):
                    if (rule.get('FromPort') == 3389 and rule.get('ToPort') == 3389 and 
                        any(ip_range.get('CidrIp') == '0.0.0.0/0' for ip_range in rule.get('IpRanges', []))):
                        rdp_open_sgs.append(sg['GroupId'])
            
            instances = ec2.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if config_manager:
                        tags = get_resource_tags(instance, 'ec2')
                        if should_exclude_resource_by_tags(tags, config_manager):
                            continue
                    
                    instance_sgs = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    if any(sg_id in rdp_open_sgs for sg_id in instance_sgs):
                        rdp_open_instances.append({
                            'AccountId': account_id,
                            'InstanceId': instance['InstanceId'],
                            'InstanceType': instance['InstanceType'],
                            'ARN': f"arn:aws:ec2:{region}:{account_id}:instance/{instance['InstanceId']}",
                            'Region': region,
                            'SecurityGroups': instance_sgs,
                            'Issue': 'RDP port 3389 open to 0.0.0.0/0',
                            'type': 'security',
                            'Risk': 'Brute force attacks',
                            'severity': 'critical',
                            'Service': 'EC2'
                        })
        except Exception as e:
            print(f"Error checking RDP open instances: {e}")
        
        return rdp_open_instances
    
    def find_database_ports_open(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find instances with database ports open to 0.0.0.0/0"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        db_open_instances = []
        
        db_ports = [3306, 5432, 1433, 27017]  # MySQL, PostgreSQL, SQL Server, MongoDB
        
        try:
            security_groups = ec2.describe_security_groups()
            db_open_sgs = []
            
            for sg in security_groups['SecurityGroups']:
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 0)
                    if (any(port >= from_port and port <= to_port for port in db_ports) and 
                        any(ip_range.get('CidrIp') == '0.0.0.0/0' for ip_range in rule.get('IpRanges', []))):
                        db_open_sgs.append(sg['GroupId'])
            
            instances = ec2.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if config_manager:
                        tags = get_resource_tags(instance, 'ec2')
                        if should_exclude_resource_by_tags(tags, config_manager):
                            continue
                    
                    instance_sgs = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    if any(sg_id in db_open_sgs for sg_id in instance_sgs):
                        db_open_instances.append({
                            'AccountId': account_id,
                            'InstanceId': instance['InstanceId'],
                            'InstanceType': instance['InstanceType'],
                            'ARN': f"arn:aws:ec2:{region}:{account_id}:instance/{instance['InstanceId']}",
                            'Region': region,
                            'SecurityGroups': instance_sgs,
                            'Issue': 'Database ports (3306/5432/1433/27017) open to 0.0.0.0/0',
                            'type': 'security',
                            'Risk': 'Unauthorized DB access',
                            'severity': 'critical',
                            'Service': 'EC2'
                        })
        except Exception as e:
            print(f"Error checking database ports: {e}")
        
        return db_open_instances
    
    def find_public_non_web(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find public IP on non-web instances"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        public_non_web = []
        
        web_ports = [80, 443, 8080, 8443]
        
        try:
            instances = ec2.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if config_manager:
                        tags = get_resource_tags(instance, 'ec2')
                        if should_exclude_resource_by_tags(tags, config_manager):
                            continue
                    
                    # Check if instance has public IP
                    public_ip = instance.get('PublicIpAddress')
                    if public_ip:
                        # Check if security groups allow web traffic
                        has_web_access = False
                        for sg in instance.get('SecurityGroups', []):
                            sg_details = ec2.describe_security_groups(GroupIds=[sg['GroupId']])
                            for sg_detail in sg_details['SecurityGroups']:
                                for rule in sg_detail.get('IpPermissions', []):
                                    from_port = rule.get('FromPort', 0)
                                    to_port = rule.get('ToPort', 0)
                                    if any(port >= from_port and port <= to_port for port in web_ports):
                                        has_web_access = True
                                        break
                        
                        if not has_web_access:
                            public_non_web.append({
                                'AccountId': account_id,
                                'InstanceId': instance['InstanceId'],
                                'InstanceType': instance['InstanceType'],
                                'ARN': f"arn:aws:ec2:{region}:{account_id}:instance/{instance['InstanceId']}",
                                'Region': region,
                                'PublicIP': public_ip,
                                'Issue': 'Public IP on non-web instance',
                                'type': 'security',
                                'Risk': 'Unnecessary attack surface',
                                'severity': 'high',
                                'Service': 'EC2'
                            })
        except Exception as e:
            print(f"Error checking public non-web instances: {e}")
        
        return public_non_web
    
    def find_old_ami(self, session: boto3.Session, region: str, days: int = 180, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find instances using AMI older than X days"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        old_ami_instances = []
        
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            instances = ec2.describe_instances()
            
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if config_manager:
                        tags = get_resource_tags(instance, 'ec2')
                        if should_exclude_resource_by_tags(tags, config_manager):
                            continue
                    
                    ami_id = instance.get('ImageId')
                    if ami_id:
                        try:
                            ami_details = ec2.describe_images(ImageIds=[ami_id])
                            if ami_details['Images']:
                                ami = ami_details['Images'][0]
                                creation_date = datetime.strptime(ami['CreationDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
                                if creation_date < cutoff_date:
                                    old_ami_instances.append({
                                        'AccountId': account_id,
                                        'InstanceId': instance['InstanceId'],
                                        'InstanceType': instance['InstanceType'],
                                        'ARN': f"arn:aws:ec2:{region}:{account_id}:instance/{instance['InstanceId']}",
                                        'Region': region,
                                        'AMI': ami_id,
                                        'AMIAge': (datetime.now() - creation_date).days,
                                        'Issue': f'AMI older than {days} days',
                                        'type': 'security',
                                        'Risk': 'Unpatched CVEs accumulation',
                                        'severity': 'high',
                                        'Service': 'EC2'
                                    })
                        except Exception:
                            continue
        except Exception as e:
            print(f"Error checking old AMI instances: {e}")
        
        return old_ami_instances
    
    def find_imdsv1(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find instances using IMDSv1"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        imdsv1_instances = []
        
        try:
            instances = ec2.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if config_manager:
                        tags = get_resource_tags(instance, 'ec2')
                        if should_exclude_resource_by_tags(tags, config_manager):
                            continue
                    
                    metadata_options = instance.get('MetadataOptions', {})
                    http_tokens = metadata_options.get('HttpTokens', 'optional')
                    
                    if http_tokens == 'optional':  # IMDSv1 enabled
                        imdsv1_instances.append({
                            'AccountId': account_id,
                            'InstanceId': instance['InstanceId'],
                            'InstanceType': instance['InstanceType'],
                            'ARN': f"arn:aws:ec2:{region}:{account_id}:instance/{instance['InstanceId']}",
                            'Region': region,
                            'HttpTokens': http_tokens,
                            'Issue': 'Using IMDSv1 (not IMDSv2)',
                            'type': 'security',
                            'Risk': 'SSRF attacks (Capital One vector)',
                            'severity': 'medium',
                            'Service': 'EC2'
                        })
        except Exception as e:
            print(f"Error checking IMDSv1 instances: {e}")
        
        return imdsv1_instances
    
    def find_unencrypted_ebs(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find instances with unencrypted EBS volumes"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        unencrypted_instances = []
        
        try:
            instances = ec2.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if config_manager:
                        tags = get_resource_tags(instance, 'ec2')
                        if should_exclude_resource_by_tags(tags, config_manager):
                            continue
                    
                    has_unencrypted = False
                    for bdm in instance.get('BlockDeviceMappings', []):
                        volume_id = bdm.get('Ebs', {}).get('VolumeId')
                        if volume_id:
                            try:
                                volume = ec2.describe_volumes(VolumeIds=[volume_id])
                                if volume['Volumes'] and not volume['Volumes'][0].get('Encrypted', False):
                                    has_unencrypted = True
                                    break
                            except Exception:
                                continue
                    
                    if has_unencrypted:
                        unencrypted_instances.append({
                            'AccountId': account_id,
                            'InstanceId': instance['InstanceId'],
                            'InstanceType': instance['InstanceType'],
                            'ARN': f"arn:aws:ec2:{region}:{account_id}:instance/{instance['InstanceId']}",
                            'Region': region,
                            'Issue': 'EBS volumes unencrypted',
                            'type': 'security',
                            'Risk': 'Data exposure if compromised',
                            'severity': 'medium',
                            'Service': 'EC2'
                        })
        except Exception as e:
            print(f"Error checking unencrypted EBS volumes: {e}")
        
        return unencrypted_instances
    
    def find_no_recent_backup(self, session: boto3.Session, region: str, days: int = 30, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Find instances with no recent AMI backup"""
        ec2 = session.client('ec2', region_name=region)
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        no_backup_instances = []
        
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            instances = ec2.describe_instances()
            
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if config_manager:
                        tags = get_resource_tags(instance, 'ec2')
                        if should_exclude_resource_by_tags(tags, config_manager):
                            continue
                    
                    instance_id = instance['InstanceId']
                    
                    # Check for recent AMIs of this instance
                    images = ec2.describe_images(
                        Owners=[account_id],
                        Filters=[
                            {'Name': 'state', 'Values': ['available']},
                            {'Name': 'description', 'Values': [f'*{instance_id}*']}
                        ]
                    )
                    
                    has_recent_backup = False
                    for image in images['Images']:
                        creation_date = datetime.strptime(image['CreationDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
                        if creation_date > cutoff_date:
                            has_recent_backup = True
                            break
                    
                    if not has_recent_backup:
                        no_backup_instances.append({
                            'AccountId': account_id,
                            'InstanceId': instance_id,
                            'InstanceType': instance['InstanceType'],
                            'ARN': f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
                            'Region': region,
                            'Issue': f'No recent AMI backup ({days}+ days)',
                            'type': 'security',
                            'Risk': 'No recovery point',
                            'severity': 'medium',
                            'Service': 'EC2'
                        })
        except Exception as e:
            print(f"Error checking recent backups: {e}")
        
        return no_backup_instances
    
    # Audit Methods
    def cost_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all cost-related audits"""
        results = []
        for check in self.cost_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def security_audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all security-related audits"""
        results = []
        for check in self.security_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager, **kwargs))
        return results
    
    def audit(self, session: boto3.Session, region: str, config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all audits (cost + security)"""
        results = []
        results.extend(self.cost_audit(session, region, config_manager=config_manager, **kwargs))
        results.extend(self.security_audit(session, region, config_manager=config_manager, **kwargs))
        return results
    
    # Individual Check Method Aliases
    def check_stopped_instances(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_stopped(session, region, **kwargs)
    
    def check_idle_instances(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_idle(session, region, **kwargs)
    
    def check_oversized_instances(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_oversized(session, region, **kwargs)
    
    def check_previous_generation(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_previous_generation(session, region, **kwargs)
    
    def check_ssh_open(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_ssh_open(session, region, **kwargs)
    
    def check_rdp_open(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_rdp_open(session, region, **kwargs)
    
    def check_database_ports_open(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_database_ports_open(session, region, **kwargs)
    
    def check_public_non_web(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_public_non_web(session, region, **kwargs)
    
    def check_old_ami(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_old_ami(session, region, **kwargs)
    
    def check_imdsv1(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_imdsv1(session, region, **kwargs)
    
    def check_unencrypted_ebs(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_unencrypted_ebs(session, region, **kwargs)
    
    def check_no_recent_backup(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        return self.find_no_recent_backup(session, region, **kwargs)