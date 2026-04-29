"""Engine Bridge — connects the new ScanEngine to the existing CLI/Scanner.

This module provides a drop-in function that the existing ComprehensiveScanner
can call to run checks via the new engine. It handles the adapter loading
and result conversion back to the legacy format.

This is the transition layer. Once all services are migrated to native plugins,
this bridge becomes unnecessary and the CLI calls the engine directly.
"""

import os
from typing import Dict, List, Any, Optional

from kosty.core.engine import ScanEngine
from kosty.core.registry import registry
from kosty.core.models import Finding


def run_via_engine(
    session: Any,
    regions: List[str],
    services: Optional[List[str]] = None,
    deep: bool = False,
    config_manager: Any = None,
    max_workers: int = 10,
    **kwargs,
) -> Dict[str, List[Dict[str, Any]]]:
    """Run a scan using the new engine and return results in legacy format.

    This function:
    1. Loads native plugins from providers/aws/services/
    2. Adapts legacy services from kosty/services/
    3. Runs the engine
    4. Converts Findings back to legacy dict format

    Args:
        session: boto3.Session
        regions: List of AWS regions to scan.
        services: Optional service filter.
        deep: Whether to run --deep checks.
        config_manager: Optional config manager.
        max_workers: Thread pool size.

    Returns:
        Dict mapping account_id to list of legacy issue dicts.
    """
    from kosty.providers.aws.adapter import adapt_all_legacy_services

    engine = ScanEngine(max_workers=max_workers)

    # Load native plugins
    plugins_dir = os.path.join(os.path.dirname(__file__), '..', 'providers', 'aws', 'services')
    if os.path.isdir(plugins_dir):
        engine.load_plugins(plugins_dir)

    # Load legacy services via adapter (only if not already loaded)
    if registry.count < 10:
        services_dir = os.path.join(os.path.dirname(__file__), '..', 'services')
        adapt_all_legacy_services(services_dir)

    # Run the engine
    result = engine.run(
        session=session,
        regions=regions,
        services=services,
        deep=deep,
        config_manager=config_manager,
        **kwargs,
    )

    # Convert to legacy format: {account_id: [issue_dicts]}
    legacy_results: Dict[str, List[Dict[str, Any]]] = {}
    for finding in result.findings:
        account = finding.account_id or 'unknown'
        if account not in legacy_results:
            legacy_results[account] = []
        legacy_results[account].append(finding.to_dict())

    return legacy_results
