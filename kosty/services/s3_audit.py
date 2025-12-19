import boto3
from ..core.tag_utils import should_exclude_resource_by_tags, get_resource_tags
from typing import List, Dict, Any
import json

class S3AuditService:
    def __init__(self):
        self.cost_checks = ['find_empty', 'find_incomplete_uploads', 'find_lifecycle_candidates']
        self.security_checks = ['find_public_read', 'find_public_write', 'find_no_encryption', 
                               'find_no_versioning', 'find_no_logging', 'find_wildcard_policy', 
                               'find_public_snapshots', 'find_no_mfa_delete']
    
    # Cost Audit Methods
    def find_empty(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find empty S3 buckets"""
        s3 = session.client('s3')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        empty_buckets = []
        
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    # Get bucket location
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location['LocationConstraint'] or 'us-east-1'
                    
                    # Check if bucket has objects
                    objects = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                    if 'Contents' not in objects:
                        empty_buckets.append({
                            'AccountId': account_id,
                            'ResourceName': bucket_name,
                            'BucketName': bucket_name,
                            'ARN': f'arn:aws:s3:::{bucket_name}',
                            'CreationDate': bucket['CreationDate'].isoformat(),
                            'Region': bucket_region,
                            'Issue': 'Empty bucket with no objects',
                            'type': 'cost',
                            'Risk': 'Waste $0.50-5/mo per bucket',
                            'severity': 'low',
                            'Service': 'S3'
                        })
                except Exception as e:
                    continue
        except Exception as e:
            print(f"Error listing buckets: {e}")
        
        return empty_buckets
    
    def find_incomplete_uploads(self, session: boto3.Session, region: str, days: int = 7, config_manager=None) -> List[Dict[str, Any]]:
        """Find incomplete multipart uploads"""
        s3 = session.client('s3')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        incomplete_uploads = []
        
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location['LocationConstraint'] or 'us-east-1'
                    
                    uploads = s3.list_multipart_uploads(Bucket=bucket_name)
                    if 'Uploads' in uploads and uploads['Uploads']:
                        incomplete_uploads.append({
                            'AccountId': account_id,
                            'ResourceName': bucket_name,
                            'BucketName': bucket_name,
                            'ARN': f'arn:aws:s3:::{bucket_name}',
                            'Region': bucket_region,
                            'IncompleteUploads': len(uploads['Uploads']),
                            'Issue': 'Incomplete multipart uploads',
                            'type': 'cost',
                            'Risk': 'Waste $10-100/mo per bucket',
                            'severity': 'medium',
                            'Service': 'S3'
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking incomplete uploads: {e}")
        
        return incomplete_uploads
    
    def find_lifecycle_candidates(self, session: boto3.Session, region: str, days: int = 90, config_manager=None) -> List[Dict[str, Any]]:
        """Find buckets needing lifecycle policies"""
        s3 = session.client('s3')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        lifecycle_candidates = []
        
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location['LocationConstraint'] or 'us-east-1'
                    
                    # Check if lifecycle policy exists
                    try:
                        s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                        has_lifecycle = True
                    except s3.exceptions.NoSuchLifecycleConfiguration:
                        has_lifecycle = False
                    
                    if not has_lifecycle:
                        # Check for old objects
                        objects = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=10)
                        if 'Contents' in objects:
                            # Calculate approximate size (simplified)
                            total_size_bytes = sum(obj.get('Size', 0) for obj in objects['Contents'])
                            size_gb = round(total_size_bytes / (1024**3), 2) if total_size_bytes > 0 else 0.1
                            
                            lifecycle_candidates.append({
                                'AccountId': account_id,
                                'ResourceName': bucket_name,
                                'BucketName': bucket_name,
                                'ARN': f'arn:aws:s3:::{bucket_name}',
                                'Region': bucket_region,
                                'region': bucket_region,
                                'ObjectCount': len(objects['Contents']),
                                'Issue': 'No lifecycle policy on old data (90+ days)',
                                'type': 'cost',
                                'Risk': 'Waste 50-70% storage costs',
                                'severity': 'high',
                                'Service': 'S3',
                                'service': 'S3',
                                'check': 'lifecycle_candidates',
                                'size_gb': size_gb,
                                'resource_id': bucket_name,
                                'resource_name': bucket_name
                            })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking lifecycle policies: {e}")
        
        return lifecycle_candidates
    
    # Security Audit Methods
    def find_public_read(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find buckets with public read access"""
        s3 = session.client('s3')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        public_buckets = []
        
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location['LocationConstraint'] or 'us-east-1'
                    
                    # Check bucket ACL
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl['Grants']:
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            if 'READ' in grant['Permission']:
                                public_buckets.append({
                                    'AccountId': account_id,
                                    'ResourceName': bucket_name,
                                    'BucketName': bucket_name,
                                    'ARN': f'arn:aws:s3:::{bucket_name}',
                                    'Region': bucket_region,
                                    'Issue': 'Public read access enabled',
                                    'type': 'security',
                                    'Risk': 'Data breach - complete bucket exposure',
                                    'severity': 'critical',
                                    'Service': 'S3',
                                    'Permission': grant['Permission']
                                })
                                break
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking public read access: {e}")
        
        return public_buckets
    
    def find_public_write(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find buckets with public write access"""
        s3 = session.client('s3')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        public_write_buckets = []
        
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location['LocationConstraint'] or 'us-east-1'
                    
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl['Grants']:
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            if 'WRITE' in grant['Permission']:
                                public_write_buckets.append({
                                    'AccountId': account_id,
                                    'ResourceName': bucket_name,
                                    'BucketName': bucket_name,
                                    'ARN': f'arn:aws:s3:::{bucket_name}',
                                    'Region': bucket_region,
                                    'Issue': 'Public write access enabled',
                                    'type': 'security',
                                    'Risk': 'Malware injection - crypto mining',
                                    'severity': 'critical',
                                    'Service': 'S3'
                                })
                                break
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking public write access: {e}")
        
        return public_write_buckets
    
    def find_no_encryption(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find buckets without encryption"""
        s3 = session.client('s3')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        unencrypted_buckets = []
        
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location['LocationConstraint'] or 'us-east-1'
                    
                    s3.get_bucket_encryption(Bucket=bucket_name)
                except s3.exceptions.NoSuchBucketEncryption:
                    unencrypted_buckets.append({
                        'AccountId': account_id,
                        'ResourceName': bucket_name,
                        'BucketName': bucket_name,
                        'ARN': f'arn:aws:s3:::{bucket_name}',
                        'Region': bucket_region,
                        'Issue': 'No encryption at rest',
                        'type': 'security',
                        'Risk': 'Data exposure if storage compromised',
                        'severity': 'critical',
                        'Service': 'S3'
                    })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking encryption: {e}")
        
        return unencrypted_buckets
    
    def find_no_versioning(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find buckets without versioning"""
        s3 = session.client('s3')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        no_versioning_buckets = []
        
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location['LocationConstraint'] or 'us-east-1'
                    
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        no_versioning_buckets.append({
                            'AccountId': account_id,
                            'ResourceName': bucket_name,
                            'BucketName': bucket_name,
                            'ARN': f'arn:aws:s3:::{bucket_name}',
                            'Region': bucket_region,
                            'Issue': 'Versioning disabled',
                            'type': 'security',
                            'Risk': 'No ransomware protection',
                            'severity': 'high',
                            'Service': 'S3'
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking versioning: {e}")
        
        return no_versioning_buckets
    
    def find_no_logging(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find buckets without access logging"""
        s3 = session.client('s3')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        no_logging_buckets = []
        
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location['LocationConstraint'] or 'us-east-1'
                    
                    logging = s3.get_bucket_logging(Bucket=bucket_name)
                    if 'LoggingEnabled' not in logging:
                        no_logging_buckets.append({
                            'AccountId': account_id,
                            'ResourceName': bucket_name,
                            'BucketName': bucket_name,
                            'ARN': f'arn:aws:s3:::{bucket_name}',
                            'Region': bucket_region,
                            'Issue': 'No access logging',
                            'type': 'security',
                            'Risk': 'Cannot audit data access',
                            'severity': 'medium',
                            'Service': 'S3'
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking logging: {e}")
        
        return no_logging_buckets
    
    def find_wildcard_policy(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find buckets with wildcard policies"""
        s3 = session.client('s3')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        wildcard_buckets = []
        
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location['LocationConstraint'] or 'us-east-1'
                    
                    policy = s3.get_bucket_policy(Bucket=bucket_name)
                    policy_doc = json.loads(policy['Policy'])
                    
                    for statement in policy_doc.get('Statement', []):
                        principal = statement.get('Principal')
                        if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                            wildcard_buckets.append({
                                'AccountId': account_id,
                                'ResourceName': bucket_name,
                                'BucketName': bucket_name,
                                'ARN': f'arn:aws:s3:::{bucket_name}',
                                'Region': bucket_region,
                                'Issue': 'Bucket policy allows wildcard principal (*)',
                                'type': 'security',
                                'Risk': 'Overly permissive access',
                                'severity': 'high',
                                'Service': 'S3'
                            })
                            break
                except Exception as e:
                    if 'NoSuchBucketPolicy' in str(e):
                        continue
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking bucket policies: {e}")
        
        return wildcard_buckets
    
    def find_public_snapshots(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find public snapshots (placeholder - S3 doesn't have snapshots)"""
        # This is more relevant for EBS, but keeping for consistency
        return []
    
    def find_no_mfa_delete(self, session: boto3.Session, region: str, config_manager=None) -> List[Dict[str, Any]]:
        """Find buckets without MFA delete"""
        s3 = session.client('s3')
        sts = session.client('sts')
        account_id = sts.get_caller_identity()['Account']
        no_mfa_buckets = []
        
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location['LocationConstraint'] or 'us-east-1'
                    
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('MfaDelete') != 'Enabled':
                        no_mfa_buckets.append({
                            'AccountId': account_id,
                            'ResourceName': bucket_name,
                            'BucketName': bucket_name,
                            'ARN': f'arn:aws:s3:::{bucket_name}',
                            'Region': bucket_region,
                            'Issue': 'No MFA delete enabled',
                            'type': 'security',
                            'Risk': 'Accidental/malicious deletion',
                            'severity': 'medium',
                            'Service': 'S3',
                            'MfaDeleteStatus': versioning.get('MfaDelete', 'Disabled')
                        })
                except Exception:
                    continue
        except Exception as e:
            print(f"Error checking MFA delete: {e}")
        
        return no_mfa_buckets
    
    # Audit Methods
    def cost_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all cost-related audits"""
        results = []
        for check in self.cost_checks:
            method = getattr(self, check)
            if check in ['find_incomplete_uploads', 'find_lifecycle_candidates']:
                results.extend(method(session, region, config_manager=config_manager, **kwargs))
            else:
                results.extend(method(session, region, config_manager=config_manager))
        return results
    
    def security_audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all security-related audits"""
        results = []
        for check in self.security_checks:
            method = getattr(self, check)
            results.extend(method(session, region, config_manager=config_manager))
        return results
    
    def audit(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        """Run all audits (cost + security)"""
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        return results
    
    # Individual Check Method Aliases
    def check_empty_buckets(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_empty(session, region)
    
    def check_incomplete_uploads(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_incomplete_uploads(session, region, **kwargs)
    
    def check_lifecycle_policy(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_lifecycle_candidates(session, region, **kwargs)
    
    def check_public_read_access(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_public_read(session, region)
    
    def check_public_write_access(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_public_write(session, region)
    
    def check_encryption_at_rest(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_no_encryption(session, region)
    
    def check_versioning_disabled(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_no_versioning(session, region)
    
    def check_access_logging(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_no_logging(session, region)
    
    def check_bucket_policy_wildcards(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_wildcard_policy(session, region)
    
    def check_public_snapshots(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_public_snapshots(session, region)
    
    def check_mfa_delete(self, session: boto3.Session, region: str,  config_manager=None, **kwargs) -> List[Dict[str, Any]]:
        return self.find_no_mfa_delete(session, region)