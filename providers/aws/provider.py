"""AWS Provider — session management and client factory.

Centralizes boto3 session creation to avoid redundant STS calls
across checks. Implements the CloudProvider interface.
"""

import boto3
from typing import List, Any, Optional, Dict
from kosty.core.provider import CloudProvider


class AWSProvider(CloudProvider):
    """AWS implementation of the CloudProvider interface."""

    def __init__(self, profile_name: Optional[str] = None, role_arn: Optional[str] = None):
        self._profile_name = profile_name
        self._role_arn = role_arn
        self._session: Optional[boto3.Session] = None
        self._account_id: Optional[str] = None
        self._client_cache: Dict[str, Any] = {}

    @property
    def name(self) -> str:
        return "aws"

    def get_session(self, **kwargs) -> boto3.Session:
        """Create or return cached boto3 session.

        Handles profile-based auth and role assumption.
        """
        if self._session:
            return self._session

        if self._profile_name:
            self._session = boto3.Session(profile_name=self._profile_name)
        else:
            self._session = boto3.Session()

        if self._role_arn:
            sts = self._session.client('sts')
            assumed = sts.assume_role(
                RoleArn=self._role_arn,
                RoleSessionName='kosty-engine'
            )
            creds = assumed['Credentials']
            self._session = boto3.Session(
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken'],
            )

        return self._session

    def get_regions(self) -> List[str]:
        """List all enabled regions for the account."""
        session = self.get_session()
        ec2 = session.client('ec2', region_name='us-east-1')
        response = ec2.describe_regions(
            Filters=[{'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}]
        )
        return [r['RegionName'] for r in response['Regions']]

    def get_account_id(self, session: Any = None) -> str:
        """Get AWS account ID, cached after first call."""
        if self._account_id:
            return self._account_id

        s = session or self.get_session()
        self._account_id = s.client('sts').get_caller_identity()['Account']
        return self._account_id

    def get_client(self, service_name: str, region: str) -> Any:
        """Get a boto3 client with caching to avoid redundant creation.

        Args:
            service_name: AWS service (e.g., 'ec2', 'iam', 's3').
            region: AWS region.

        Returns:
            Cached boto3 client.
        """
        cache_key = f"{service_name}:{region}"
        if cache_key not in self._client_cache:
            session = self.get_session()
            self._client_cache[cache_key] = session.client(service_name, region_name=region)
        return self._client_cache[cache_key]
