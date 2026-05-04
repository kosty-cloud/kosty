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

from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from .registry import registry
from .loader import PluginLoader
from .models import Finding, ScanResult


class ScanEngine:
    """Core scan orchestrator. Provider-agnostic.

    The engine doesn't know about AWS, boto3, or any specific service.
    It delegates to registered checks and collects standardized Findings.
    """

    def __init__(self, max_workers: int = 10):
        self._loader = PluginLoader()
        self._max_workers = max_workers

    def load_plugins(self, path: str, debug: bool = False) -> int:
        """Load plugins from a directory. Checks self-register on import.

        Args:
            path: Directory containing plugin modules.
            debug: Forward to PluginLoader for per-module load output.

        Returns:
            Number of modules loaded.
        """
        return self._loader.load_directory(path, debug=debug)


    def run(
        self,
        session: Any,
        regions: List[str],
        services: Optional[List[str]] = None,
        provider: str = "aws",
        deep: bool = False,
        config_manager: Any = None,
        on_check_complete=None,
        debug: bool = False,
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

        # Split global checks (IAM, S3, etc.) from regional ones.
        # Global checks run once on the first region to avoid N duplicate scans.
        global_checks = [c for c in checks if c['metadata'].region_scope == 'global']
        regional_checks = [c for c in checks if c['metadata'].region_scope != 'global']

        first_region = regions[0] if regions else None

        if debug:
            import sys
            print(
                f"[DEBUG] engine.run: {len(checks)} checks total"
                f" ({len(global_checks)} global, {len(regional_checks)} regional)"
                f" regions={regions}",
                file=sys.stderr,
            )

        for region in regions:
            # Global checks only on first region
            checks_for_region = regional_checks + (global_checks if region == first_region else [])
            region_findings, region_errors = self._run_checks_for_region(
                checks_for_region, session, region, deep=deep,
                config_manager=config_manager,
                on_check_complete=on_check_complete,
                debug=debug,
                **kwargs
            )
            result.findings.extend(region_findings)
            result.errors.extend(region_errors)

        result.errors.extend(self._loader.errors)
        return result

    def _run_checks_for_region(
        self,
        checks: List[Dict[str, Any]],
        session: Any,
        region: str,
        on_check_complete=None,
        debug: bool = False,
        **kwargs,
    ) -> tuple:
        """Run all checks for a single region with thread pool.

        Returns:
            Tuple of (findings, errors).
        """
        import sys
        import time
        findings = []
        errors = []

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = {}
            for check in checks:
                future = executor.submit(
                    self._execute_check, check, session, region, **kwargs
                )
                futures[future] = check['metadata']

            for future in as_completed(futures):
                metadata = futures[future]
                t0 = time.monotonic()
                try:
                    check_findings = future.result()
                    findings.extend(check_findings)
                    if debug:
                        elapsed = time.monotonic() - t0
                        print(
                            f"[DEBUG] {metadata.check_id} [{region}]"
                            f" findings={len(check_findings)} t={elapsed:.2f}s",
                            file=sys.stderr,
                        )
                except Exception as e:
                    errors.append(f"{metadata.check_id} [{region}]: {type(e).__name__}: {e}")
                    if debug:
                        elapsed = time.monotonic() - t0
                        print(
                            f"[DEBUG] {metadata.check_id} [{region}]"
                            f" ERROR {type(e).__name__}: {e} t={elapsed:.2f}s",
                            file=sys.stderr,
                        )
                finally:
                    if on_check_complete:
                        on_check_complete(metadata.service)

        return findings, errors

    def _execute_check(
        self,
        check: Dict[str, Any],
        session: Any,
        region: str,
        **kwargs,
    ) -> List[Finding]:
        """Execute a single check function.

        Exceptions are intentionally re-raised so _run_checks_for_region
        can capture them with timing and route them to ScanResult.errors.
        """
        func = check['func']
        metadata = check['metadata']
        result = func(session=session, region=region, **kwargs)
        if isinstance(result, list):
            if metadata.compliance_ids:
                for f in result:
                    if hasattr(f, 'compliance_ids') and not f.compliance_ids:
                        f.compliance_ids = metadata.compliance_ids
            return result
        return []

    @property
    def registered_checks(self) -> int:
        """Number of checks currently registered."""
        return registry.count

    @property
    def loader_errors(self) -> List[str]:
        """Any errors encountered during plugin loading."""
        return self._loader.errors
