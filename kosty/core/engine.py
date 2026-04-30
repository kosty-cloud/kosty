"""Scan Engine — the importable core of Kosty.

This is what the Pro version imports. It orchestrates check discovery,
execution, and result aggregation without any CLI dependency.

Usage (programmatic):
    from kosty.core.engine import ScanEngine

    engine = ScanEngine()
    engine.load_plugins('providers/aws/services')
    engine.load_plugins('/opt/kosty-pro/plugins')  # optional premium path

    results = engine.run(
        session=boto3.Session(),
        regions=['eu-west-3'],
        services=['iam', 's3'],  # optional filter
    )
"""

import boto3
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from .registry import registry
from .loader import PluginLoader
from .models import Finding, ScanResult, Severity, FindingType


class ScanEngine:
    """Core scan orchestrator. Provider-agnostic.

    The engine doesn't know about AWS, boto3, or any specific service.
    It delegates to registered checks and collects standardized Findings.
    """

    def __init__(self, max_workers: int = 10):
        self._loader = PluginLoader()
        self._max_workers = max_workers

    def load_plugins(self, path: str) -> int:
        """Load plugins from a directory. Checks self-register on import.

        Args:
            path: Directory containing plugin modules.

        Returns:
            Number of modules loaded.
        """
        return self._loader.load_directory(path)


    def run(
        self,
        session: Any,
        regions: List[str],
        services: Optional[List[str]] = None,
        provider: str = "aws",
        deep: bool = False,
        config_manager: Any = None,
        on_check_complete=None,
        **kwargs,
    ) -> ScanResult:
        """Execute all registered checks and return aggregated results.

        Args:
            session: Provider session (e.g., boto3.Session).
            regions: List of regions to scan.
            services: Optional filter — only run checks for these services.
            provider: Provider name filter (default: "aws").
            deep: Whether to run checks that require --deep.
            config_manager: Optional config manager for thresholds/exclusions.
            on_check_complete: Optional callback(service: str) called after
                               each check completes. Used for progress display.

        Returns:
            ScanResult with all findings and any errors.
        """
        result = ScanResult()
        checks = registry.get_checks_by_provider(provider)

        if services:
            services_lower = [s.lower() for s in services]
            checks = [c for c in checks if c['metadata'].service.lower() in services_lower]

        if not deep:
            checks = [c for c in checks if not c['metadata'].requires_deep]

        for region in regions:
            region_findings = self._run_checks_for_region(
                checks, session, region, deep=deep,
                config_manager=config_manager,
                on_check_complete=on_check_complete,
                **kwargs
            )
            result.findings.extend(region_findings)

        result.errors.extend(self._loader.errors)
        return result

    def _run_checks_for_region(
        self,
        checks: List[Dict[str, Any]],
        session: Any,
        region: str,
        on_check_complete=None,
        **kwargs,
    ) -> List[Finding]:
        """Run all checks for a single region with thread pool."""
        findings = []

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = {}
            for check in checks:
                future = executor.submit(
                    self._execute_check, check, session, region, **kwargs
                )
                futures[future] = check['metadata']

            for future in as_completed(futures):
                metadata = futures[future]
                try:
                    check_findings = future.result()
                    findings.extend(check_findings)
                except Exception:
                    pass
                finally:
                    if on_check_complete:
                        on_check_complete(metadata.service)

        return findings

    def _execute_check(
        self,
        check: Dict[str, Any],
        session: Any,
        region: str,
        **kwargs,
    ) -> List[Finding]:
        """Execute a single check function.

        Args:
            check: Registry entry with 'func' and 'metadata'.
            session: Provider session.
            region: Target region.

        Returns:
            List of Findings produced by the check.
        """
        func = check['func']
        metadata = check['metadata']
        try:
            result = func(session=session, region=region, **kwargs)
            if isinstance(result, list):
                # Inject compliance_ids from metadata into findings
                if metadata.compliance_ids:
                    for f in result:
                        if hasattr(f, 'compliance_ids') and not f.compliance_ids:
                            f.compliance_ids = metadata.compliance_ids
                return result
            return []
        except Exception:
            return []

    @property
    def registered_checks(self) -> int:
        """Number of checks currently registered."""
        return registry.count

    @property
    def loader_errors(self) -> List[str]:
        """Any errors encountered during plugin loading."""
        return self._loader.errors
