import asyncio
import os
import sys
import importlib
from typing import Dict, Any, List, Tuple
from .reporter import CostOptimizationReporter
from .progress import ProgressBar
from .executor import ServiceExecutor

class ComprehensiveScanner:
    def __init__(self, organization: bool, regions: List[str], max_workers: int, cross_account_role: str = 'OrganizationAccountAccessRole', org_admin_account_id: str = None, config_manager=None, session=None):
        self.organization = organization
        self.regions = regions if isinstance(regions, list) else [regions]
        self.max_workers = max_workers
        self.cross_account_role = cross_account_role
        self.org_admin_account_id = org_admin_account_id
        self.reporter = CostOptimizationReporter()
        self.reporter.set_scan_context(organization, org_admin_account_id)
        
        # Config manager for exclusions and thresholds
        if config_manager is None:
            from .config import ConfigManager
            config_manager = ConfigManager()
        self.config_manager = config_manager
        
        # AWS session (with AssumeRole if configured)
        self.session = session
        
        self.services = self._discover_audit_services()
    
    def _discover_audit_services(self) -> List[Tuple[str, Any]]:
        """Dynamically discover all audit services"""
        services = []
        excluded_services = []
        services_dir = os.path.join(os.path.dirname(__file__), '..', 'services')
        
        for filename in os.listdir(services_dir):
            if filename.endswith('_audit.py') and not filename.startswith('__'):
                module_name = filename[:-3]  # Remove .py
                service_name = module_name.replace('_audit', '')
                
                # Check if service is excluded
                if self.config_manager.should_exclude_service(service_name):
                    excluded_services.append(service_name.upper())
                    continue
                
                try:
                    # Import the module
                    module = importlib.import_module(f'kosty.services.{module_name}')
                    
                    # Find the audit service class
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and 
                            attr_name.endswith('AuditService') and 
                            hasattr(attr, 'audit')):
                            services.append((service_name, attr()))
                            break
                except Exception as e:
                    print(f"Warning: Could not load {module_name}: {e}")
                    continue
        
        if excluded_services:
            print(f"⚠️  {', '.join(excluded_services)} service(s) excluded by config")
        
        return services
    
    async def _validate_organization_access(self) -> bool:
        """Validate organization access before starting scan"""
        if not self.organization:
            return True  # Single account mode, no validation needed
        
        try:
            import boto3
            from concurrent.futures import ThreadPoolExecutor
            
            # Use profile session if available
            validation_session = self.session if self.session else boto3.Session()
            
            # If org admin account is specified, assume role there first
            if self.org_admin_account_id:
                sts_client = validation_session.client('sts')
                loop = asyncio.get_event_loop()
                
                with ThreadPoolExecutor() as executor:
                    assumed_role = await loop.run_in_executor(
                        executor,
                        lambda: sts_client.assume_role(
                            RoleArn=f'arn:aws:iam::{self.org_admin_account_id}:role/{self.cross_account_role}',
                            RoleSessionName='kosty-org-validation'
                        )
                    )
                
                validation_session = boto3.Session(
                    aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                    aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                    aws_session_token=assumed_role['Credentials']['SessionToken']
                )
            
            # Test Organizations access
            org_client = validation_session.client('organizations')
            loop = asyncio.get_event_loop()
            
            with ThreadPoolExecutor() as executor:
                await loop.run_in_executor(executor, org_client.list_accounts)
            
            return True
            
        except Exception as e:
            error_msg = str(e)
            print(f"\n❌ Organization access validation failed:")
            
            if "AWSOrganizationsNotInUseException" in error_msg:
                print("   • Your account is not a member of an organization")
                print("   • Use single account mode by removing --organization flag")
            elif "AccessDenied" in error_msg:
                print("   • Insufficient permissions to access Organizations API")
                if self.org_admin_account_id:
                    print(f"   • Check if role '{self.cross_account_role}' exists in account {self.org_admin_account_id}")
                else:
                    print("   • Consider using --org-admin-account-id parameter")
            else:
                print(f"   • {error_msg}")
            
            print("\n💡 Suggestions:")
            print("   1. Run without --organization for single account scan")
            print("   2. Ensure proper IAM permissions for Organizations API")
            print("   3. Use --org-admin-account-id if needed")
            return False
    
    async def run_comprehensive_scan(self) -> CostOptimizationReporter:
        """Run all optimization scans and generate report"""
        print("🚀 KOSTY - AWS Cost Optimization Comprehensive Scan")
        print("=" * 60)
        
        # Validate organization access first
        if not await self._validate_organization_access():
            print("\n🛑 Scan aborted due to access validation failure")
            return self.reporter
        
        print("🔍 What will be scanned:")
        print("  • Cost optimization opportunities across all services")
        print("  • Security vulnerabilities and misconfigurations")
        print("  • Unused resources and waste identification")
        print("  • Oversized instances and over-provisioned resources")
        print("")
        print(f"📊 Services to scan: {len(self.services)}")
        regions_str = ', '.join(self.regions)
        print(f"🌍 Regions: {regions_str}")
        print(f"🏢 Scope: {'Organization-wide' if self.organization else 'Single account'}")
        print(f"⚡ Parallel workers: {self.max_workers}")
        print("=" * 60)
        
        progress = ProgressBar(len(self.services), "Scanning")
        
        # Run all services in parallel
        semaphore = asyncio.Semaphore(self.max_workers)
        service_results = {}  # service_name -> issue count
        
        async def _audit_service(service_name, service_instance):
            async with semaphore:
                try:
                    executor = ServiceExecutor(service_instance, self.organization, self.regions, self.max_workers, self.cross_account_role, self.org_admin_account_id, config_manager=self.config_manager, session=self.session, parent_progress=progress)
                    results = await executor.execute('audit')
                    
                    svc_issues = 0
                    # Process results for each account
                    for account_id, account_results in results.items():
                        if isinstance(account_results, list):
                            self.reporter.add_results(service_name, 'audit', account_results, account_id)
                            svc_issues += len(account_results)
                        elif isinstance(account_results, str) and account_results.startswith("Error"):
                            pass  # errors logged by executor
                        else:
                            self.reporter.add_results(service_name, 'audit', [], account_id)
                    
                    service_results[service_name] = svc_issues
                            
                except Exception as e:
                    service_results[service_name] = f"Error: {e}"
                finally:
                    progress.update()
        
        # Suppress stdout from worker threads so progress bar on stderr stays clean
        _orig_stdout = sys.stdout
        sys.stdout = open(os.devnull, 'w')
        try:
            await asyncio.gather(*[
                _audit_service(name, instance) for name, instance in self.services
            ])
        finally:
            sys.stdout.close()
            sys.stdout = _orig_stdout
        
        # Print per-service summary table
        total_issues = sum(v for v in service_results.values() if isinstance(v, int))
        print("\n" + "=" * 60)
        print("✅ Comprehensive scan completed!")
        print(f"📊 Total issues found: {total_issues}")
        print("─" * 60)
        for svc_name, count in sorted(service_results.items(), key=lambda x: x[1] if isinstance(x[1], int) else -1, reverse=True):
            if isinstance(count, int):
                if count > 0:
                    print(f"  {svc_name.upper():>12}  {count:>4} issues")
                else:
                    print(f"  {svc_name.upper():>12}     ✅ clean")
            else:
                print(f"  {svc_name.upper():>12}     ❌ {count}")
        print("─" * 60)
        print(f"💰 Ready to generate cost optimization reports")
        print("=" * 60)
        
        return self.reporter