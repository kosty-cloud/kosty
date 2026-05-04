"""Check Registry — central catalog of all available checks.

The registry is the single source of truth for what checks exist,
which provider they belong to, and how to execute them. Checks
self-register via the @register_check decorator at import time.

Usage:
    from kosty.core.registry import registry, register_check

    @register_check(
        check_id="aws-iam-001",
        service="IAM",
        provider="aws",
        finding_type=FindingType.SECURITY,
        description="Root account has access keys"
    )
    def check_root_access_keys(session, region, **kwargs):
        ...
"""

from typing import Callable, Dict, List, Optional, Any
from .models import CheckMetadata, FindingType


class CheckRegistry:
    """Stores and retrieves registered checks.

    Thread-safe singleton. Plugins register checks at import time.
    The engine queries the registry to discover what to run.
    """

    def __init__(self):
        self._checks: Dict[str, Dict[str, Any]] = {}

    def register(
        self,
        check_id: str,
        service: str,
        provider: str,
        finding_type: FindingType,
        description: str = "",
        requires_deep: bool = False,
        compliance_ids: Dict = None,
        region_scope: str = 'regional',
    ) -> Callable:
        """Decorator factory that registers a check function.

        Args:
            check_id: Unique identifier (e.g., "aws-iam-001").
            service: Service name (e.g., "IAM", "S3").
            provider: Cloud provider (e.g., "aws").
            finding_type: Cost or Security.
            description: Human-readable description.
            requires_deep: Whether this check needs --deep flag.
            compliance_ids: Optional mapping of framework to control IDs.
            region_scope: 'regional' (default) or 'global' — global checks
                          run only once per scan regardless of region count.

        Returns:
            Decorator that registers the function and returns it unchanged.
        """
        def decorator(func: Callable) -> Callable:
            self._checks[check_id] = {
                'metadata': CheckMetadata(
                    check_id=check_id,
                    service=service,
                    provider=provider,
                    finding_type=finding_type,
                    description=description,
                    requires_deep=requires_deep,
                    compliance_ids=compliance_ids or {},
                    region_scope=region_scope,
                ),
                'func': func,
            }
            return func
        return decorator

    def get_check(self, check_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single check by ID."""
        return self._checks.get(check_id)

    def get_checks_by_service(self, service: str) -> List[Dict[str, Any]]:
        """Retrieve all checks for a given service."""
        return [
            c for c in self._checks.values()
            if c['metadata'].service.lower() == service.lower()
        ]

    def get_checks_by_provider(self, provider: str) -> List[Dict[str, Any]]:
        """Retrieve all checks for a given provider."""
        return [
            c for c in self._checks.values()
            if c['metadata'].provider.lower() == provider.lower()
        ]

    def get_all_checks(self) -> List[Dict[str, Any]]:
        """Retrieve all registered checks."""
        return list(self._checks.values())

    def list_check_ids(self) -> List[str]:
        """List all registered check IDs."""
        return list(self._checks.keys())

    @property
    def count(self) -> int:
        """Number of checks currently registered."""
        return len(self._checks)


# Global singleton — all plugins register against this instance.
registry = CheckRegistry()

# Convenience alias for the decorator.
register_check = registry.register
