"""Configuration management system for Kosty"""

import os
import yaml
import boto3
import fnmatch
from pathlib import Path
from typing import Dict, Any, Optional, List
from .exceptions import ConfigValidationError, ConfigNotFoundError


# Valid AWS regions
VALID_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
    'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    'ap-southeast-1', 'ap-southeast-2', 'ap-east-1',
    'ca-central-1', 'sa-east-1', 'me-south-1', 'af-south-1'
]

# Valid Kosty services
VALID_SERVICES = [
    'ec2', 's3', 'rds', 'lambda', 'ebs', 'iam', 'eip',
    'lb', 'nat', 'sg', 'cloudwatch', 'dynamodb',
    'route53', 'apigateway', 'backup', 'snapshots'
]

# Hardcoded defaults
DEFAULT_CONFIG = {
    'organization': False,
    'regions': ['us-east-1'],
    'max_workers': 5,
    'output': 'console',
    'cross_account_role': 'OrganizationAccountAccessRole',
    'org_admin_account_id': None,
    'save_to': None,
    'role_arn': None,
    'aws_profile': None,
    'mfa_serial': None,
    'duration_seconds': 3600
}

DEFAULT_THRESHOLDS = {
    'ec2_cpu': 20,
    'rds_cpu': 20,
    'lambda_memory': 512,
    'stopped_days': 7,
    'idle_days': 7,
    'old_snapshot_days': 30
}


class ConfigManager:
    """Manage configuration with YAML profiles"""
    
    def __init__(self, config_file: Optional[str] = None, profile: str = "default"):
        self.config_file = config_file
        self.profile = profile
        self.config = {}
        self.raw_config = {}
        
        # Load and validate config
        self._load_config()
        self._validate_config()
    
    def _find_config_file(self) -> Optional[str]:
        """Find config: --config-file > ./kosty.yaml > ~/.kosty/config.yaml"""
        if self.config_file:
            if os.path.exists(self.config_file):
                return self.config_file
            raise ConfigNotFoundError(f"Config file not found: {self.config_file}")
        
        # Check current directory
        for filename in ['kosty.yaml', 'kosty.yml', '.kosty.yaml', '.kosty.yml']:
            if os.path.exists(filename):
                return filename
        
        # Check home directory
        home_config = Path.home() / '.kosty' / 'config.yaml'
        if home_config.exists():
            return str(home_config)
        
        return None
    
    def _load_config(self) -> None:
        """Load config from YAML file"""
        config_path = self._find_config_file()
        
        if not config_path:
            self.raw_config = {'default': {}}
            self.config = DEFAULT_CONFIG.copy()
            return
        
        try:
            with open(config_path, 'r') as f:
                self.raw_config = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigValidationError(f"Invalid YAML syntax in {config_path}: {e}")
        except Exception as e:
            raise ConfigValidationError(f"Failed to load config file {config_path}: {e}")
        
        self.config = DEFAULT_CONFIG.copy()
        
        if 'default' in self.raw_config:
            self.config.update(self.raw_config['default'])
        
        if self.profile != 'default':
            profiles = self.raw_config.get('profiles', {})
            if self.profile in profiles:
                self.config.update(profiles[self.profile])
            else:
                print(f"⚠️  Profile '{self.profile}' not found, using 'default'")
    
    def _validate_config(self) -> None:
        """Validate config values"""
        errors = []
        
        regions = self.config.get('regions', [])
        if isinstance(regions, str):
            regions = [regions]
        
        for region in regions:
            if region not in VALID_REGIONS:
                errors.append(f"Invalid region: {region}")
        
        excluded_services = self.get_exclusions().get('services', [])
        for service in excluded_services:
            if service not in VALID_SERVICES:
                errors.append(f"Unknown service: {service}")
        
        excluded_arns = self.get_exclusions().get('arns', [])
        for arn in excluded_arns:
            if not arn.startswith('arn:aws:'):
                errors.append(f"Invalid ARN: {arn}")
        
        excluded_tags = self.get_exclusions().get('tags', [])
        for tag in excluded_tags:
            if not isinstance(tag, dict):
                errors.append("Tag exclusion must be a dict with 'key' field")
            elif 'key' not in tag:
                errors.append("Tag exclusion must have 'key' field")
        
        if 'organization' in self.config and not isinstance(self.config['organization'], bool):
            errors.append("'organization' must be boolean")
        
        if 'max_workers' in self.config:
            if not isinstance(self.config['max_workers'], int) or self.config['max_workers'] <= 0:
                errors.append("'max_workers' must be positive integer")
        
        if 'duration_seconds' in self.config:
            if not isinstance(self.config['duration_seconds'], int) or self.config['duration_seconds'] <= 0:
                errors.append("'duration_seconds' must be positive integer")
        
        thresholds = self.get_thresholds()
        for key, value in thresholds.items():
            if not isinstance(value, (int, float)) or value <= 0:
                errors.append(f"Invalid threshold '{key}': {value}")
        
        if errors:
            print("\n❌ Configuration validation failed:\n")
            for error in errors:
                print(f"  • {error}")
            print("\n🛑 Fix errors before running Kosty.\n")
            raise ConfigValidationError('\n'.join(errors))
    
    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)
    
    def get_thresholds(self) -> Dict[str, Any]:
        """Get thresholds: global + profile overrides"""
        thresholds = DEFAULT_THRESHOLDS.copy()
        
        if 'thresholds' in self.raw_config:
            thresholds.update(self.raw_config['thresholds'])
        
        if self.profile != 'default':
            profiles = self.raw_config.get('profiles', {})
            if self.profile in profiles:
                profile_thresholds = profiles[self.profile].get('thresholds', {})
                thresholds.update(profile_thresholds)
        
        return thresholds
    
    def get_exclusions(self) -> Dict[str, List]:
        """Get exclusions: global + profile additions"""
        exclusions = {
            'accounts': [],
            'regions': [],
            'services': [],
            'arns': [],
            'tags': []
        }
        
        if 'exclude' in self.raw_config:
            for key in exclusions.keys():
                exclusions[key].extend(self.raw_config['exclude'].get(key, []))
        
        if self.profile != 'default':
            profiles = self.raw_config.get('profiles', {})
            if self.profile in profiles:
                profile_exclude = profiles[self.profile].get('exclude', {})
                for key in exclusions.keys():
                    exclusions[key].extend(profile_exclude.get(key, []))
        
        return exclusions
    
    def should_exclude_account(self, account_id: str) -> bool:
        excluded_accounts = self.get_exclusions().get('accounts', [])
        return account_id in excluded_accounts
    
    def should_exclude_region(self, region: str) -> bool:
        excluded_regions = self.get_exclusions().get('regions', [])
        return region in excluded_regions
    
    def should_exclude_service(self, service: str) -> bool:
        excluded_services = self.get_exclusions().get('services', [])
        return service in excluded_services
    
    def should_exclude_arn(self, arn: str) -> bool:
        """Check if ARN matches exclusion pattern (wildcards supported)"""
        excluded_arns = self.get_exclusions().get('arns', [])
        for pattern in excluded_arns:
            if fnmatch.fnmatch(arn, pattern):
                return True
        return False
    
    def should_exclude_by_tags(self, resource_tags: List[Dict[str, str]]) -> bool:
        """Check if resource should be excluded based on tags"""
        if not resource_tags:
            return False
        
        excluded_tags = self.get_exclusions().get('tags', [])
        if not excluded_tags:
            return False
        
        for excluded_tag in excluded_tags:
            if not isinstance(excluded_tag, dict):
                continue
            
            key = excluded_tag.get('key')
            value = excluded_tag.get('value')
            
            if not key:
                continue
            
            for resource_tag in resource_tags:
                tag_key = resource_tag.get('Key') or resource_tag.get('key')
                tag_value = resource_tag.get('Value') or resource_tag.get('value')
                
                if tag_key == key:
                    if value is None:
                        return True
                    if tag_value == value:
                        return True
        
        return False
    
    def merge_with_cli_args(self, cli_args: Dict[str, Any]) -> Dict[str, Any]:
        """Merge config with CLI args (CLI takes priority)"""
        merged = self.config.copy()
        for key, value in cli_args.items():
            if value is not None:
                merged[key] = value
        return merged
    
    def get_all_profiles(self) -> List[str]:
        """Get list of all profile names from config"""
        profiles = ['default']
        if 'profiles' in self.raw_config:
            profiles.extend(self.raw_config['profiles'].keys())
        return profiles
    
    def get_aws_session(self) -> boto3.Session:
        """Create AWS session with AssumeRole/MFA if configured"""
        role_arn = self.get('role_arn')
        aws_profile = self.get('aws_profile')
        mfa_serial = self.get('mfa_serial')
        duration = self.get('duration_seconds', 3600)
        
        # Priority: role_arn > aws_profile > default credentials
        if role_arn:
            # AssumeRole flow
            mfa_token = None
            if mfa_serial:
                mfa_token = input(f"🔐 Enter MFA token for {mfa_serial}: ")
            
            sts = boto3.client('sts')
            
            assume_role_params = {
                'RoleArn': role_arn,
                'RoleSessionName': f'kosty-{self.profile}',
                'DurationSeconds': duration
            }
            
            if mfa_serial and mfa_token:
                assume_role_params['SerialNumber'] = mfa_serial
                assume_role_params['TokenCode'] = mfa_token
            
            try:
                response = sts.assume_role(**assume_role_params)
                
                return boto3.Session(
                    aws_access_key_id=response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                    aws_session_token=response['Credentials']['SessionToken']
                )
            except Exception as e:
                config_file = self._find_config_file() or 'No config file'
                print(f"\nError: Failed to assume role")
                print(f"  Profile: {self.profile}")
                print(f"  Config: {config_file}")
                print(f"  Role ARN: {role_arn}")
                print(f"  Reason: {e}")
                print("\nCannot proceed without valid role access. Aborting.\n")
                raise SystemExit(1)
        
        elif aws_profile:
            # Use AWS CLI profile
            try:
                return boto3.Session(profile_name=aws_profile)
            except Exception as e:
                config_file = self._find_config_file() or 'No config file'
                print(f"\nError: Failed to use AWS profile")
                print(f"  Profile: {self.profile}")
                print(f"  Config: {config_file}")
                print(f"  AWS Profile: {aws_profile}")
                print(f"  Reason: {e}")
                print(f"\nMake sure '{aws_profile}' exists in ~/.aws/credentials or ~/.aws/config\n")
                raise SystemExit(1)
        
        else:
            # Use default credentials (env vars, instance role, default profile)
            return boto3.Session()
