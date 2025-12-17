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
    """Manages Kosty configuration with YAML profiles"""
    
    def __init__(self, config_file: Optional[str] = None, profile: str = "default"):
        """Initialize configuration manager
        
        Args:
            config_file: Path to config file (optional)
            profile: Profile name to use (default: "default")
        """
        self.config_file = config_file
        self.profile = profile
        self.config = {}
        self.raw_config = {}
        
        # Load and validate config
        self._load_config()
        self._validate_config()
    
    def _find_config_file(self) -> Optional[str]:
        """Find configuration file in order of priority
        
        Priority:
        1. --config-file argument
        2. ./kosty.yaml (current directory)
        3. ~/.kosty/config.yaml (home directory)
        
        Returns:
            Path to config file or None
        """
        # 1. Explicit config file
        if self.config_file:
            if os.path.exists(self.config_file):
                return self.config_file
            raise ConfigNotFoundError(f"Config file not found: {self.config_file}")
        
        # 2. Current directory
        for filename in ['kosty.yaml', 'kosty.yml', '.kosty.yaml', '.kosty.yml']:
            if os.path.exists(filename):
                return filename
        
        # 3. Home directory
        home_config = Path.home() / '.kosty' / 'config.yaml'
        if home_config.exists():
            return str(home_config)
        
        return None
    
    def _load_config(self) -> None:
        """Load configuration from YAML file"""
        config_path = self._find_config_file()
        
        if not config_path:
            # No config file found, use defaults
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
        
        # Start with defaults
        self.config = DEFAULT_CONFIG.copy()
        
        # Merge with default profile
        if 'default' in self.raw_config:
            self.config.update(self.raw_config['default'])
        
        # Merge with selected profile (if not default)
        if self.profile != 'default':
            profiles = self.raw_config.get('profiles', {})
            if self.profile in profiles:
                self.config.update(profiles[self.profile])
            else:
                print(f"⚠️  Profile '{self.profile}' not found, using 'default'")
    
    def _validate_config(self) -> None:
        """Validate configuration values"""
        errors = []
        
        # Validate regions
        regions = self.config.get('regions', [])
        if isinstance(regions, str):
            regions = [regions]
        
        for region in regions:
            if region not in VALID_REGIONS:
                errors.append(f"Invalid region: '{region}'")
        
        # Validate excluded services
        excluded_services = self.get_exclusions().get('services', [])
        for service in excluded_services:
            if service not in VALID_SERVICES:
                errors.append(f"Unknown service: '{service}'")
        
        # Validate ARN format
        excluded_arns = self.get_exclusions().get('arns', [])
        for arn in excluded_arns:
            if not arn.startswith('arn:aws:'):
                errors.append(f"Invalid ARN format: '{arn}' (must start with 'arn:aws:')")
        
        # Validate boolean types
        if 'organization' in self.config and not isinstance(self.config['organization'], bool):
            errors.append("'organization' must be boolean (true/false)")
        
        # Validate integer types
        if 'max_workers' in self.config:
            if not isinstance(self.config['max_workers'], int) or self.config['max_workers'] <= 0:
                errors.append("'max_workers' must be positive integer")
        
        if 'duration_seconds' in self.config:
            if not isinstance(self.config['duration_seconds'], int) or self.config['duration_seconds'] <= 0:
                errors.append("'duration_seconds' must be positive integer")
        
        # Validate thresholds
        thresholds = self.get_thresholds()
        for key, value in thresholds.items():
            if not isinstance(value, (int, float)) or value <= 0:
                errors.append(f"Threshold '{key}' must be positive number, got: {value}")
        
        # Raise if errors found
        if errors:
            print("\n❌ Configuration validation failed:\n")
            for error in errors:
                print(f"  • {error}")
            print("\n🛑 Fix configuration errors before running Kosty.\n")
            raise ConfigValidationError('\n'.join(errors))
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with fallback
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)
    
    def get_thresholds(self) -> Dict[str, Any]:
        """Get all thresholds with merge logic (3A)
        
        Returns:
            Merged thresholds (global + profile overrides)
        """
        # Start with defaults
        thresholds = DEFAULT_THRESHOLDS.copy()
        
        # Merge with global thresholds
        if 'thresholds' in self.raw_config:
            thresholds.update(self.raw_config['thresholds'])
        
        # Merge with profile thresholds (override)
        if self.profile != 'default':
            profiles = self.raw_config.get('profiles', {})
            if self.profile in profiles:
                profile_thresholds = profiles[self.profile].get('thresholds', {})
                thresholds.update(profile_thresholds)
        
        return thresholds
    
    def get_exclusions(self) -> Dict[str, List[str]]:
        """Get all exclusions with merge logic (2A)
        
        Returns:
            Merged exclusions (global + profile additions)
        """
        exclusions = {
            'accounts': [],
            'regions': [],
            'services': [],
            'arns': []
        }
        
        # Add global exclusions
        if 'exclude' in self.raw_config:
            for key in exclusions.keys():
                exclusions[key].extend(self.raw_config['exclude'].get(key, []))
        
        # Add profile exclusions (cumulative)
        if self.profile != 'default':
            profiles = self.raw_config.get('profiles', {})
            if self.profile in profiles:
                profile_exclude = profiles[self.profile].get('exclude', {})
                for key in exclusions.keys():
                    exclusions[key].extend(profile_exclude.get(key, []))
        
        return exclusions
    
    def should_exclude_account(self, account_id: str) -> bool:
        """Check if account should be excluded
        
        Args:
            account_id: AWS account ID
            
        Returns:
            True if account should be excluded
        """
        excluded_accounts = self.get_exclusions().get('accounts', [])
        return account_id in excluded_accounts
    
    def should_exclude_region(self, region: str) -> bool:
        """Check if region should be excluded
        
        Args:
            region: AWS region code
            
        Returns:
            True if region should be excluded
        """
        excluded_regions = self.get_exclusions().get('regions', [])
        return region in excluded_regions
    
    def should_exclude_service(self, service: str) -> bool:
        """Check if service should be excluded
        
        Args:
            service: Service name (e.g., 'ec2', 's3')
            
        Returns:
            True if service should be excluded
        """
        excluded_services = self.get_exclusions().get('services', [])
        return service in excluded_services
    
    def should_exclude_arn(self, arn: str) -> bool:
        """Check if ARN should be excluded (supports wildcards)
        
        Args:
            arn: AWS ARN
            
        Returns:
            True if ARN matches exclusion pattern
        """
        excluded_arns = self.get_exclusions().get('arns', [])
        
        for pattern in excluded_arns:
            if fnmatch.fnmatch(arn, pattern):
                return True
        
        return False
    
    def merge_with_cli_args(self, cli_args: Dict[str, Any]) -> Dict[str, Any]:
        """Merge configuration with CLI arguments
        
        Priority: CLI args > Profile config > Default config > Hardcoded defaults
        
        Args:
            cli_args: Dictionary of CLI arguments
            
        Returns:
            Merged configuration
        """
        merged = self.config.copy()
        
        # Override with CLI args (only non-None values)
        for key, value in cli_args.items():
            if value is not None:
                merged[key] = value
        
        return merged
    
    def get_aws_session(self) -> boto3.Session:
        """Create AWS session with AssumeRole and MFA support
        
        Returns:
            Configured boto3 Session
        """
        role_arn = self.get('role_arn')
        mfa_serial = self.get('mfa_serial')
        duration = self.get('duration_seconds', 3600)
        
        # No role_arn, use default credentials
        if not role_arn:
            return boto3.Session()
        
        # Prompt for MFA if configured
        mfa_token = None
        if mfa_serial:
            mfa_token = input(f"🔐 Enter MFA token for {mfa_serial}: ")
        
        # AssumeRole
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
            print(f"\n❌ Failed to assume role: {e}")
            print("💡 Using default credentials instead\n")
            return boto3.Session()
