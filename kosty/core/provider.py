"""Provider Interface — abstract base for cloud providers.

The core engine interacts with providers through this interface.
Each provider (AWS, GCP, Azure) implements it to handle
session management and region discovery.
"""

from abc import ABC, abstractmethod
from typing import List, Any


class CloudProvider(ABC):
    """Abstract base class for cloud provider implementations."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier (e.g., 'aws', 'gcp', 'azure')."""
        ...

    @abstractmethod
    def get_session(self, **kwargs) -> Any:
        """Create an authenticated session for this provider.

        Returns:
            Provider-specific session object (e.g., boto3.Session).
        """
        ...

    @abstractmethod
    def get_regions(self) -> List[str]:
        """List available regions for this provider.

        Returns:
            List of region identifiers.
        """
        ...

    @abstractmethod
    def get_account_id(self, session: Any) -> str:
        """Retrieve the current account/project identifier.

        Args:
            session: Provider session.

        Returns:
            Account or project ID string.
        """
        ...
