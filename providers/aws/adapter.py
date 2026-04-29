"""Service Adapter — bridges legacy *_audit.py services into the plugin registry.

The adapter imports each legacy service class, introspects its check methods,
and registers them into the CheckRegistry. This allows the new ScanEngine to
execute legacy checks without any modification to the original service files.

The legacy services continue to work with the old CLI path simultaneously.
Migration to native plugin format happens progressively, one service at a time.
"""

import os
import importlib
from typing import List, Dict, Any, Optional

from kosty.core.registry import registry
from kosty.core.models import Finding, FindingType, Severity


# Map legacy severity strings to the Severity enum
_SEVERITY_MAP = {
    'critical': Severity.CRITICAL,
    'high': Severity.HIGH,
    'medium': Severity.MEDIUM,
    'low': Severity.LOW,
    'info': Severity.INFO,
}


def _convert_legacy_result(item: Dict[str, Any], check_id: str) -> Finding:
    """Convert a legacy issue dictionary to a Finding dataclass.

    Args:
        item: Legacy issue dict from a *_audit.py check method.
        check_id: The assigned check ID for this finding.

    Returns:
        Standardized Finding instance.
    """
    severity_str = (item.get('severity') or item.get('Severity') or 'medium').lower()
    finding_type_str = (item.get('type') or item.get('Type') or 'security').lower()

    return Finding(
        check_id=check_id,
        service=item.get('Service', ''),
        resource_id=item.get('ResourceId') or item.get('resource_id') or item.get('InstanceId') or item.get('BucketName') or '',
        region=item.get('Region') or item.get('region') or '',
        account_id=item.get('AccountId') or '',
        issue=item.get('Issue') or '',
        severity=_SEVERITY_MAP.get(severity_str, Severity.MEDIUM),
        finding_type=FindingType.COST if finding_type_str == 'cost' else FindingType.SECURITY,
        risk=item.get('Risk') or '',
        resource_name=item.get('ResourceName') or item.get('resource_name') or '',
        arn=item.get('ARN') or '',
        details=item.get('Details') or {},
        monthly_savings=item.get('monthly_savings') or item.get('monthly_cost') or 0.0,
    )


def adapt_legacy_service(service_module_name: str, service_name: str) -> int:
    """Import a legacy service and register all its checks into the registry.

    Introspects the service class for methods starting with 'find_' and
    registers each one as a check in the global registry.

    Args:
        service_module_name: Fully qualified module name (e.g., 'kosty.services.iam_audit').
        service_name: Short service name (e.g., 'iam', 'ec2').

    Returns:
        Number of checks registered from this service.
    """
    try:
        module = importlib.import_module(service_module_name)
    except Exception:
        return 0

    # Find the audit service class
    service_class = None
    for attr_name in dir(module):
        attr = getattr(module, attr_name)
        if (isinstance(attr, type) and attr_name.endswith('AuditService') and hasattr(attr, 'audit')):
            service_class = attr
            break

    if not service_class:
        return 0

    # Instantiate to access check lists
    instance = service_class()
    registered = 0
    check_index = 1

    # Collect all find_* methods
    all_checks = []
    for method_name in dir(instance):
        if not method_name.startswith('find_') or method_name.startswith('find_no_') is False and method_name.startswith('find_') is False:
            continue
        if not method_name.startswith('find_'):
            continue
        method = getattr(instance, method_name, None)
        if not callable(method):
            continue
        all_checks.append(method_name)

    for method_name in sorted(all_checks):
        method = getattr(instance, method_name)
        check_id = f"aws-{service_name}-{check_index:03d}"

        # Determine finding type from the check lists
        finding_type = FindingType.SECURITY
        if hasattr(instance, 'cost_checks') and method_name in instance.cost_checks:
            finding_type = FindingType.COST

        # Create a wrapper that calls the legacy method and converts results
        def make_wrapper(m, cid, svc_name):
            def wrapper(session, region, **kwargs):
                try:
                    results = m(session, region, **kwargs)
                    return [_convert_legacy_result(item, cid) for item in results if isinstance(item, dict)]
                except Exception:
                    return []
            wrapper.__name__ = m.__name__
            wrapper.__doc__ = m.__doc__
            return wrapper

        wrapped = make_wrapper(method, check_id, service_name)

        # Register into the global registry
        registry._checks[check_id] = {
            'metadata': __import__('kosty.core.models', fromlist=['CheckMetadata']).CheckMetadata(
                check_id=check_id,
                service=service_name.upper(),
                provider='aws',
                finding_type=finding_type,
                description=method.__doc__ or '',
            ),
            'func': wrapped,
        }

        registered += 1
        check_index += 1

    return registered


def adapt_all_legacy_services(services_dir: Optional[str] = None) -> int:
    """Discover and adapt all legacy services from kosty/services/.

    Args:
        services_dir: Path to the services directory. Defaults to kosty/services/.

    Returns:
        Total number of checks registered across all services.
    """
    if services_dir is None:
        services_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'kosty', 'services')
    services_dir = os.path.abspath(services_dir)

    total = 0
    for filename in sorted(os.listdir(services_dir)):
        if not filename.endswith('_audit.py') or filename.startswith('__'):
            continue

        service_name = filename.replace('_audit.py', '')
        module_name = f"kosty.services.{filename[:-3]}"
        total += adapt_legacy_service(module_name, service_name)

    return total
