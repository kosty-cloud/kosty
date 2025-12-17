"""Multi-profile audit runner with parallel execution"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import ConfigManager
from .scanner import ComprehensiveScanner


class MultiProfileRunner:
    """Run audits across multiple profiles in parallel"""
    
    def __init__(self, config_file: Optional[str] = None, profiles: Optional[List[str]] = None):
        self.config_file = config_file
        self.profiles = profiles
        self.results = {}
        self.errors = {}
        
        # Load base config to get all profiles if not specified
        if not self.profiles:
            base_config = ConfigManager(config_file=config_file, profile='default')
            self.profiles = base_config.get_all_profiles()
    
    def _run_profile_audit(self, profile: str, cli_args: Dict[str, Any]) -> Dict[str, Any]:
        """Run audit for a single profile"""
        try:
            print(f"\n[{profile}] Starting audit...")
            
            # Load config for this profile
            config_manager = ConfigManager(config_file=self.config_file, profile=profile)
            
            # Merge with CLI args
            final_config = config_manager.merge_with_cli_args(cli_args)
            
            # Handle regions
            if final_config.get('regions'):
                if isinstance(final_config['regions'], str):
                    reg_list = [r.strip() for r in final_config['regions'].split(',')]
                else:
                    reg_list = final_config['regions']
            elif final_config.get('region'):
                reg_list = [final_config['region']]
            else:
                reg_list = ['us-east-1']
            
            # Get AWS session
            session = config_manager.get_aws_session()
            
            # Run scan
            scanner = ComprehensiveScanner(
                final_config.get('organization', False),
                reg_list,
                final_config.get('max_workers', 5),
                final_config.get('cross_account_role', 'OrganizationAccountAccessRole'),
                final_config.get('org_admin_account_id'),
                config_manager=config_manager,
                session=session
            )
            
            reporter = asyncio.run(scanner.run_comprehensive_scan())
            
            # Calculate totals
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
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            print(f"[{profile}] ✗ Failed: {str(e)}")
            return {
                'profile': profile,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def run_parallel(self, cli_args: Dict[str, Any], max_parallel: int = 3) -> Dict[str, Any]:
        """Run audits for all profiles in parallel"""
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
                        'timestamp': datetime.utcnow().isoformat()
                    }
        
        return self._generate_summary()
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary of all profile results"""
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
                    'timestamp': result['timestamp']
                }
                for profile, result in self.results.items()
            },
            'errors': self.errors
        }
    
    def save_reports(self, output_format: str = 'json', output_dir: str = 'output') -> List[str]:
        """Save individual reports for each profile"""
        Path(output_dir).mkdir(exist_ok=True)
        saved_files = []
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        
        # Save individual profile reports
        for profile, result in self.results.items():
            if result['status'] != 'success':
                continue
            
            reporter = result['reporter']
            
            if output_format in ['json', 'all']:
                filename = f"{output_dir}/kosty_audit_{profile}_{timestamp}.json"
                
                # Build JSON with profile info
                report_data = {
                    'profile': profile,
                    'timestamp': result['timestamp'],
                    'total_issues': result['total_issues'],
                    'total_savings': result['total_savings'],
                    'results': reporter.results
                }
                
                with open(filename, 'w') as f:
                    json.dump(report_data, f, indent=2, default=str)
                
                saved_files.append(filename)
                print(f"📄 [{profile}] JSON report: {filename}")
            
            if output_format in ['csv', 'all']:
                filename = f"{output_dir}/kosty_audit_{profile}_{timestamp}.csv"
                # Use existing CSV generation from reporter
                csv_content = self._generate_csv_for_profile(reporter, profile)
                with open(filename, 'w') as f:
                    f.write(csv_content)
                saved_files.append(filename)
                print(f"📊 [{profile}] CSV report: {filename}")
        
        # Save summary report
        summary_file = f"{output_dir}/kosty_summary_{timestamp}.json"
        summary = self._generate_summary()
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        saved_files.append(summary_file)
        print(f"\n📋 Summary report: {summary_file}")
        
        return saved_files
    
    def _generate_csv_for_profile(self, reporter, profile: str) -> str:
        """Generate CSV content for a profile"""
        lines = []
        lines.append("Profile,Account,Region,Service,Check,Severity,Count,Monthly Savings,Annual Savings,Resource IDs")
        
        for account_id, services in reporter.results.items():
            for service, checks in services.items():
                for check_name, check_data in checks.items():
                    region = check_data.get('region', 'N/A')
                    severity = check_data.get('severity', 'Medium')
                    count = check_data.get('count', 0)
                    monthly = check_data.get('monthly_savings', 0)
                    annual = monthly * 12
                    resources = '; '.join(check_data.get('resources', [])[:5])
                    
                    lines.append(
                        f"{profile},{account_id},{region},{service},{check_name},"
                        f"{severity},{count},${monthly:.2f},${annual:.2f},\"{resources}\""
                    )
        
        return '\n'.join(lines)
    
    def print_summary(self) -> None:
        """Print console summary of all profiles"""
        summary = self._generate_summary()
        
        print("\n" + "="*70)
        print("MULTI-PROFILE AUDIT SUMMARY")
        print("="*70)
        print(f"Total Profiles: {summary['total_profiles']}")
        print(f"Successful: {summary['successful_profiles']}")
        print(f"Failed: {summary['failed_profiles']}")
        print(f"\nTotal Issues: {summary['total_issues']}")
        print(f"Total Savings: ${summary['total_savings']:,.2f}/month (${summary['total_savings']*12:,.2f}/year)")
        print("\n" + "-"*70)
        print(f"{'Profile':<20} {'Issues':<10} {'Monthly Savings':<20}")
        print("-"*70)
        
        for profile, data in summary['profiles'].items():
            print(f"{profile:<20} {data['issues']:<10} ${data['savings']:>10,.2f}/month")
        
        if summary['errors']:
            print("\n" + "-"*70)
            print("ERRORS:")
            for profile, error in summary['errors'].items():
                print(f"  [{profile}] {error.get('error', 'Unknown error')}")
        
        print("="*70 + "\n")
