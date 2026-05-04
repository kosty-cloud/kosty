"""Multi-profile audit runner.

Runs kosty audit against multiple profiles from kosty.yaml in parallel,
then aggregates the results into per-profile reports and a cross-profile
summary. Useful for MSPs or anyone managing several AWS accounts with
separate credential profiles.

Each profile runs in its own thread with its own asyncio event loop —
profiles are fully isolated, so a failure in one doesn't affect the others.
"""

import asyncio
import json
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import ConfigManager
from .engine_scanner import EngineScanner


class MultiProfileRunner:
    """Orchestrates parallel audits across all profiles defined in kosty.yaml.

    Profiles are discovered from the config file at init time unless an
    explicit list is passed. Results and errors are stored separately so
    callers can inspect partial success (some profiles failed, others didn't).
    """

    def __init__(self, config_file: Optional[str] = None, profiles: Optional[List[str]] = None):
        self.config_file = config_file
        self.results: Dict[str, Any] = {}
        self.errors: Dict[str, Any] = {}

        if profiles:
            self.profiles = profiles
        else:
            base_config = ConfigManager(config_file=config_file, profile='default')
            self.profiles = base_config.get_all_profiles()

    def _run_profile_audit(self, profile: str, cli_args: Dict[str, Any]) -> Dict[str, Any]:
        """Run a full audit for one profile and return a result dict.

        Called from a ThreadPoolExecutor worker, so it creates its own
        asyncio event loop via asyncio.run(). Exceptions are caught and
        returned as error results rather than propagated — one broken
        profile shouldn't abort the others.
        """
        try:
            print(f"\n[{profile}] Starting audit...")

            config_manager = ConfigManager(config_file=self.config_file, profile=profile)
            final_config = config_manager.merge_with_cli_args(cli_args)

            if final_config.get('regions'):
                reg_list = (
                    [r.strip() for r in final_config['regions'].split(',')]
                    if isinstance(final_config['regions'], str)
                    else final_config['regions']
                )
            elif final_config.get('region'):
                reg_list = [final_config['region']]
            else:
                reg_list = ['us-east-1']

            session = config_manager.get_aws_session()
            scanner = EngineScanner(
                final_config.get('organization', False),
                reg_list,
                final_config.get('max_workers', 5),
                final_config.get('cross_account_role', 'OrganizationAccountAccessRole'),
                final_config.get('org_admin_account_id'),
                config_manager=config_manager,
                session=session,
            )

            reporter = asyncio.run(scanner.run_comprehensive_scan())

            total_issues = sum(
                sum(cmd['count'] for cmd in svc.values())
                for acc in reporter.results.values()
                for svc in acc.values()
            )
            total_savings = sum(
                sum(cmd.get('monthly_savings', 0) for cmd in svc.values())
                for acc in reporter.results.values()
                for svc in acc.values()
            )

            print(f"[{profile}] ✓ Completed: {total_issues} issues, ${total_savings:,.2f}/month")

            return {
                'profile': profile,
                'status': 'success',
                'reporter': reporter,
                'total_issues': total_issues,
                'total_savings': total_savings,
                'timestamp': datetime.utcnow().isoformat(),
            }

        except Exception as e:
            print(f"[{profile}] ✗ Failed: {e}")
            return {
                'profile': profile,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat(),
            }

    def run_parallel(self, cli_args: Dict[str, Any], max_parallel: int = 3) -> Dict[str, Any]:
        """Kick off all profile audits concurrently and wait for completion.

        max_parallel controls how many profiles run simultaneously. Keep it
        low (3-5) to avoid hitting AWS API rate limits across accounts.
        """
        print(f"\n🚀 Running audits for {len(self.profiles)} profiles in parallel (max {max_parallel} concurrent)")
        print(f"📋 Profiles: {', '.join(self.profiles)}\n")

        with ThreadPoolExecutor(max_workers=max_parallel) as executor:
            futures = {
                executor.submit(self._run_profile_audit, profile, cli_args): profile
                for profile in self.profiles
            }
            for future in as_completed(futures):
                profile = futures[future]
                try:
                    result = future.result()
                    if result['status'] == 'success':
                        self.results[profile] = result
                    else:
                        self.errors[profile] = result
                except Exception as e:
                    self.errors[profile] = {
                        'profile': profile,
                        'status': 'error',
                        'error': str(e),
                        'timestamp': datetime.utcnow().isoformat(),
                    }

        return self._generate_summary()

    def _generate_summary(self) -> Dict[str, Any]:
        """Aggregate totals across all successful profiles."""
        total_issues = sum(r['total_issues'] for r in self.results.values())
        total_savings = sum(r['total_savings'] for r in self.results.values())

        return {
            'timestamp': datetime.utcnow().isoformat(),
            'total_profiles': len(self.profiles),
            'successful_profiles': len(self.results),
            'failed_profiles': len(self.errors),
            'total_issues': total_issues,
            'total_savings': total_savings,
            'profiles': {
                profile: {
                    'issues': result['total_issues'],
                    'savings': result['total_savings'],
                    'timestamp': result['timestamp'],
                }
                for profile, result in self.results.items()
            },
            'errors': self.errors,
        }

    def save_reports(self, output_format: str = 'json', output_dir: str = 'output') -> List[str]:
        """Write per-profile reports and a cross-profile summary to disk.

        JSON reports include the full finding list. The summary JSON is
        always written regardless of output_format — it's lightweight and
        useful for CI pipelines that just want the totals.
        """
        Path(output_dir).resolve().mkdir(parents=True, exist_ok=True)
        saved_files = []
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        output_dir = str(Path(output_dir).resolve())

        for profile, result in self.results.items():
            if result['status'] != 'success':
                continue

            reporter = result['reporter']
            # Sanitise profile name for use in filenames — profiles can contain
            # arbitrary characters from kosty.yaml including path separators.
            safe_profile = re.sub(r'[^\w-]', '_', profile)

            if output_format in ('json', 'all'):
                filename = f"{output_dir}/kosty_audit_{safe_profile}_{timestamp}.json"
                report_data = {
                    'profile': profile,
                    'timestamp': result['timestamp'],
                    'total_issues': result['total_issues'],
                    'total_savings': result['total_savings'],
                    'results': reporter.results,
                }
                with open(filename, 'w') as f:
                    json.dump(report_data, f, indent=2, default=str)
                saved_files.append(filename)
                print(f"📄 [{profile}] JSON report: {filename}")

            if output_format in ('csv', 'all'):
                filename = f"{output_dir}/kosty_audit_{safe_profile}_{timestamp}.csv"
                csv_content = self._generate_csv_for_profile(reporter, profile)
                with open(filename, 'w') as f:
                    f.write(csv_content)
                saved_files.append(filename)
                print(f"📊 [{profile}] CSV report: {filename}")

        summary_file = f"{output_dir}/kosty_summary_{timestamp}.json"
        with open(summary_file, 'w') as f:
            json.dump(self._generate_summary(), f, indent=2, default=str)
        saved_files.append(summary_file)
        print(f"\n📋 Summary report: {summary_file}")

        return saved_files

    def _generate_csv_for_profile(self, reporter, profile: str) -> str:
        """Build a CSV string from a reporter's results for one profile.

        One row per service/command pair. Resource IDs are the first 5
        findings for that group — enough for a quick spreadsheet review.
        """
        lines = ['Profile,Account,Service,Command,Count,Monthly Savings,Annual Savings,Resource IDs']

        for account_id, services in reporter.results.items():
            for service, checks in services.items():
                for check_name, check_data in checks.items():
                    count = check_data.get('count', 0)
                    monthly = check_data.get('monthly_savings', 0)
                    annual = monthly * 12
                    resource_ids = '; '.join(
                        item.get('ResourceId') or item.get('resource_id', 'unknown')
                        for item in check_data.get('items', [])[:5]
                    )
                    lines.append(
                        f'{profile},{account_id},{service},{check_name},'
                        f'{count},${monthly:.2f},${annual:.2f},"{resource_ids}"'
                    )

        return '\n'.join(lines)

    def print_summary(self) -> None:
        """Print a formatted cross-profile summary table to stdout."""
        summary = self._generate_summary()

        print("\n" + "=" * 70)
        print("MULTI-PROFILE AUDIT SUMMARY")
        print("=" * 70)
        print(f"Total Profiles: {summary['total_profiles']}")
        print(f"Successful: {summary['successful_profiles']}")
        print(f"Failed: {summary['failed_profiles']}")
        print(f"\nTotal Issues: {summary['total_issues']}")
        print(f"Total Savings: ${summary['total_savings']:,.2f}/month (${summary['total_savings'] * 12:,.2f}/year)")
        print("\n" + "-" * 70)
        print(f"{'Profile':<20} {'Issues':<10} {'Monthly Savings':<20}")
        print("-" * 70)

        for profile, data in summary['profiles'].items():
            print(f"{profile:<20} {data['issues']:<10} ${data['savings']:>10,.2f}/month")

        if summary['errors']:
            print("\n" + "-" * 70)
            print("ERRORS:")
            for profile, error in summary['errors'].items():
                print(f"  [{profile}] {error.get('error', 'Unknown error')}")

        print("=" * 70 + "\n")
