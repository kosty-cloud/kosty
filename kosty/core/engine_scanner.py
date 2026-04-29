"""Engine-based scanner — replaces ComprehensiveScanner for `kosty audit`.

Uses the plugin engine (ScanEngine) to discover and run checks, then feeds
results into the existing CostOptimizationReporter for backward-compatible
output (console, JSON, CSV, dashboard).

This is the production path for v3.0.0. The legacy ComprehensiveScanner
remains available as a fallback but is no longer the default.
"""

import os
import sys
import asyncio
from typing import List, Optional, Any
from concurrent.futures import ThreadPoolExecutor

from .engine import ScanEngine
from .reporter import CostOptimizationReporter
from .models import Finding, FindingType
from .progress import ProgressBar


class EngineScanner:
    """Scan orchestrator backed by the plugin engine."""

    def __init__(
        self,
        organization: bool,
        regions: List[str],
        max_workers: int,
        cross_account_role: str = 'OrganizationAccountAccessRole',
        org_admin_account_id: str = None,
        config_manager=None,
        session=None,
    ):
        self.organization = organization
        self.regions = regions if isinstance(regions, list) else [regions]
        self.max_workers = max_workers
        self.cross_account_role = cross_account_role
        self.org_admin_account_id = org_admin_account_id
        self.config_manager = config_manager
        self.session = session

        self.reporter = CostOptimizationReporter()
        self.reporter.set_scan_context(organization, org_admin_account_id)

        self._engine = ScanEngine(max_workers=max_workers)
        self._load_plugins()

    def _load_plugins(self):
        """Load native plugins from providers/aws/services/."""
        plugins_dir = os.path.join(
            os.path.dirname(__file__), '..', 'providers', 'aws', 'services'
        )
        plugins_dir = os.path.abspath(plugins_dir)
        if os.path.isdir(plugins_dir):
            self._engine.load_plugins(plugins_dir)

    async def run_comprehensive_scan(self) -> CostOptimizationReporter:
        """Run all registered checks and return a populated reporter."""
        import boto3

        print("🚀 KOSTY - AWS Cost Optimization Comprehensive Scan")
        print("=" * 60)

        # Validate org access
        if self.organization and not await self._validate_organization_access():
            print("\n🛑 Scan aborted due to access validation failure")
            return self.reporter

        # Determine excluded services
        excluded = []
        if self.config_manager:
            from .registry import registry
            all_services = set(
                c['metadata'].service.lower()
                for c in registry.get_checks_by_provider('aws')
            )
            excluded = [
                s for s in all_services
                if self.config_manager.should_exclude_service(s)
            ]
            if excluded:
                print(f"⚠️  {', '.join(s.upper() for s in excluded)} service(s) excluded by config")

        # Count services that will run
        from .registry import registry
        active_checks = registry.get_checks_by_provider('aws')
        active_services = set(c['metadata'].service for c in active_checks)
        if excluded:
            active_services -= set(s.upper() for s in excluded)
            active_services -= set(s for s in excluded)

        print("🔍 What will be scanned:")
        print("  • Cost optimization opportunities across all services")
        print("  • Security vulnerabilities and misconfigurations")
        print("")
        print(f"📊 Services to scan: {len(active_services)}")
        print(f"🌍 Regions: {', '.join(self.regions)}")
        print(f"🏢 Scope: {'Organization-wide' if self.organization else 'Single account'}")
        print(f"⚡ Parallel workers: {self.max_workers}")
        print("=" * 60)

        if self.organization:
            await self._run_organization_scan(excluded)
        else:
            await self._run_single_account_scan(excluded)

        return self.reporter

    async def _run_single_account_scan(self, excluded_services: List[str]):
        """Run engine against a single account."""
        import boto3

        session = self.session or boto3.Session()

        # Determine service filter
        services_filter = None
        if excluded_services:
            services_filter = None  # engine handles all, we filter below

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: self._engine.run(
                session=session,
                regions=self.regions,
                services=None,
                deep=False,
                config_manager=self.config_manager,
            )
        )

        # Filter out excluded services
        findings = result.findings
        if excluded_services:
            excluded_lower = set(s.lower() for s in excluded_services)
            findings = [f for f in findings if f.service.lower() not in excluded_lower]

        # Group findings by service and feed into reporter
        self._feed_reporter(findings)

        # Print summary
        total = len(findings)
        print("\n" + "=" * 60)
        print("✅ Comprehensive scan completed!")
        print(f"📊 Total issues found: {total}")
        print("=" * 60)

    async def _run_organization_scan(self, excluded_services: List[str]):
        """Run engine across all organization accounts."""
        import boto3

        session = self.session or boto3.Session()

        # Discover accounts
        accounts = await self._list_org_accounts(session)
        if not accounts:
            print("❌ No accounts found in organization")
            return

        # Filter excluded accounts
        if self.config_manager:
            accounts = [
                a for a in accounts
                if not self.config_manager.should_exclude_account(a)
            ]

        print(f"\n📋 Scanning {len(accounts)} accounts...")
        progress = ProgressBar(len(accounts), "Scanning accounts")

        semaphore = asyncio.Semaphore(self.max_workers)
        all_findings: List[Finding] = []

        async def scan_account(account_id: str):
            async with semaphore:
                try:
                    assumed_session = await self._assume_role(session, account_id)
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(
                        None,
                        lambda s=assumed_session: self._engine.run(
                            session=s,
                            regions=self.regions,
                            deep=False,
                            config_manager=self.config_manager,
                        )
                    )
                    return result.findings
                except Exception as e:
                    print(f"  ✗ {account_id}: {e}", file=sys.stderr)
                    return []
                finally:
                    progress.update()

        tasks = [scan_account(acc) for acc in accounts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)

        # Filter excluded
        if excluded_services:
            excluded_lower = set(s.lower() for s in excluded_services)
            all_findings = [f for f in all_findings if f.service.lower() not in excluded_lower]

        self._feed_reporter(all_findings)

        total = len(all_findings)
        print("\n" + "=" * 60)
        print("✅ Organization scan completed!")
        print(f"📊 Total issues found: {total}")
        print("=" * 60)

    def _feed_reporter(self, findings: List[Finding]):
        """Convert findings to legacy format and feed into reporter."""
        # Group by (account_id, service)
        grouped = {}
        for f in findings:
            key = (f.account_id or 'current', f.service.lower())
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(f.to_dict())

        for (account_id, service), items in grouped.items():
            self.reporter.add_results(service, 'audit', items, account_id)

    async def _validate_organization_access(self) -> bool:
        """Validate organization access before starting scan."""
        try:
            import boto3
            validation_session = self.session or boto3.Session()

            if self.org_admin_account_id:
                validation_session = await self._assume_role(
                    validation_session, self.org_admin_account_id
                )

            org_client = validation_session.client('organizations')
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, org_client.list_accounts)
            return True
        except Exception as e:
            error_msg = str(e)
            print(f"\n❌ Organization access validation failed:")
            if "AWSOrganizationsNotInUseException" in error_msg:
                print("   • Your account is not a member of an organization")
            elif "AccessDenied" in error_msg:
                print("   • Insufficient permissions to access Organizations API")
            else:
                print(f"   • {error_msg}")
            return False

    async def _list_org_accounts(self, session) -> List[str]:
        """List all active accounts in the organization."""
        try:
            org_session = session
            if self.org_admin_account_id:
                org_session = await self._assume_role(session, self.org_admin_account_id)

            org_client = org_session.client('organizations')
            accounts = []
            paginator = org_client.get_paginator('list_accounts')
            for page in paginator.paginate():
                for acc in page['Accounts']:
                    if acc['Status'] == 'ACTIVE':
                        accounts.append(acc['Id'])
            return accounts
        except Exception as e:
            print(f"❌ Failed to list accounts: {e}")
            return []

    async def _assume_role(self, session, account_id: str):
        """Assume cross-account role and return new session."""
        import boto3

        sts = session.client('sts')
        loop = asyncio.get_event_loop()
        assumed = await loop.run_in_executor(
            None,
            lambda: sts.assume_role(
                RoleArn=f'arn:aws:iam::{account_id}:role/{self.cross_account_role}',
                RoleSessionName=f'kosty-{account_id}'
            )
        )
        return boto3.Session(
            aws_access_key_id=assumed['Credentials']['AccessKeyId'],
            aws_secret_access_key=assumed['Credentials']['SecretAccessKey'],
            aws_session_token=assumed['Credentials']['SessionToken'],
        )
