import asyncio
import boto3
import json
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional
from datetime import datetime
from .progress import ProgressBar, SpinnerProgress
from .storage import StorageManager

class ServiceExecutor:
    def __init__(self, service, organization: bool, regions: List[str], max_workers: int = 5, cross_account_role: str = 'OrganizationAccountAccessRole', org_admin_account_id: str = None, config_manager=None, session=None):
        self.service = service
        self.organization = organization
        self.regions = regions
        self.max_workers = max_workers
        self.cross_account_role = cross_account_role
        self.org_admin_account_id = org_admin_account_id
        self.storage_manager = StorageManager()
        
        # Config manager for exclusions
        if config_manager is None:
            from .config import ConfigManager
            config_manager = ConfigManager()
        self.config_manager = config_manager
        
        # Session from profile or default
        self.session = session if session else boto3.Session()
        
    def _generate_filename(self, method_name: str, results: Dict[str, Any], file_format: str) -> str:
        """Generate descriptive filename based on scan parameters"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Determine service name from class name
        service_name = getattr(self.service, '__class__', type(self.service)).__name__.lower()
        if 'auditservice' in service_name:
            service_name = service_name.replace('auditservice', '')
        
        # Determine scope
        if self.organization:
            if self.org_admin_account_id:
                scope = f"org_{self.org_admin_account_id}"
            else:
                scope = "org"
        else:
            # Single account - get account ID from results
            account_id = list(results.keys())[0] if results else "unknown"
            scope = account_id
        
        # Build filename components
        parts = ['kosty']
        
        # Add service or "full" for comprehensive scans
        if service_name and service_name != 'comprehensive':
            parts.append(service_name)
        else:
            parts.append('full')
        
        # Add method if not standard audit
        if method_name != 'audit':
            parts.append(method_name)
        
        # Add scope
        parts.append(scope)
        
        # Add timestamp
        parts.append(timestamp)
        
        return f"{'_'.join(parts)}.{file_format}"
    
    def _standardize_results_format(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize results format for dashboard compatibility"""
        standardized = {}
        
        # Get service name from class
        service_name = getattr(self.service, '__class__', type(self.service)).__name__.lower()
        if 'auditservice' in service_name:
            service_name = service_name.replace('auditservice', '')
        
        for account_id, items in results.items():
            if isinstance(items, list):
                # Create dashboard-compatible structure: account -> service -> command -> {count, items}
                standardized[account_id] = {
                    service_name: {
                        'audit': {
                            'count': len(items),
                            'items': []
                        }
                    }
                }
                
                # Ensure all items have required fields for dashboard
                for item in items:
                    if isinstance(item, dict):
                        # Ensure Service field exists
                        if 'Service' not in item:
                            item['Service'] = service_name.upper()
                        
                        # Ensure AccountId field exists
                        if 'AccountId' not in item:
                            item['AccountId'] = account_id
                        
                        standardized[account_id][service_name]['audit']['items'].append(item)
            else:
                standardized[account_id] = items
        
        return standardized
        
    async def execute(self, method_name: str, output_format: str = 'console', save_to: Optional[str] = None, *args, **kwargs) -> Dict[str, Any]:
        # Validate save location upfront if specified
        if save_to and output_format in ['json', 'csv']:
            print(f"\n🔍 Validating save location: {save_to}")
            if not await self.storage_manager.validate_save_location(save_to):
                print("\n🛑 Save location validation failed. Aborting scan.")
                return {}
            print("✅ Save location validated successfully")
        
        # Display command description before starting
        self._display_command_description(method_name)
        
        spinner = SpinnerProgress(f"Running {method_name}")
        spinner.start()
        
        try:
            if self.organization:
                results = await self._execute_organization(method_name, *args, **kwargs)
            else:
                results = await self._execute_single_account(method_name, *args, **kwargs)
            
            # Display results based on output format
            await self._display_results(results, method_name, output_format, save_to)
            return results
        except ValueError as e:
            spinner.stop()
            print(f"\n{str(e)}")
            print("\n💡 Try running without --organization flag for single account scan.")
            return {}
        finally:
            spinner.stop()
    
    def _display_command_description(self, method_name: str):
        """Display what the command will do before execution"""
        descriptions = {
            'audit': '🔍 Running comprehensive audit (cost + security checks)',
            'cost_audit': '💰 Running cost optimization audit',
            'security_audit': '🔒 Running security audit',
            'check_empty_buckets': '🪣 Checking for empty S3 buckets',
            'check_unused_functions': '⚡ Checking for unused Lambda functions',
            'check_idle_instances': '💤 Checking for idle RDS instances',
            'check_oversized_instances': '📏 Checking for oversized instances',
            'check_ssh_open': '🚪 Checking for SSH ports open to internet',
            'check_public_read_access': '🌐 Checking for public read access',
            'check_unattached_eips': '🔗 Checking for unattached Elastic IPs',
            'check_unused_security_groups': '🛡️ Checking for unused security groups',
            'check_root_access_keys': '🔑 Checking for root account access keys',
            'check_old_access_keys': '⏰ Checking for old access keys',
            'check_orphan_volumes': '💾 Checking for orphaned EBS volumes',
            'check_unused_alarms': '⏰ Checking for unused CloudWatch alarms',
            'check_lbs_with_no_healthy_targets': '⚖️ Checking for load balancers with no targets'
        }
        
        description = descriptions.get(method_name, f'🔍 Running {method_name.replace("_", " ")}')
        scope = '🏢 Organization-wide' if self.organization else '📊 Single account'
        if isinstance(self.regions, list):
            regions_str = ', '.join(self.regions)
        else:
            regions_str = str(self.regions)
        region_info = f'📍 Regions: {regions_str}'
        
        print(f"\n{description}")
        print(f"{scope} | {region_info} | 👥 Workers: {self.max_workers}")
        print("─" * 60)
    
    async def _display_results(self, results: Dict[str, Any], method_name: str, output_format: str = 'console', save_to: Optional[str] = None):
        """Display results based on output format"""
        total_issues = 0
        
        for account_id, items in results.items():
            if isinstance(items, list):
                total_issues += len(items)
        
        # Always show console output with resource details
        for account_id, items in results.items():
            if isinstance(items, list) and items:
                print(f"\n📊 Account: {account_id}")
                print(f"  🔍 {method_name}: {len(items)} issues")
                
                # Display detailed items
                for item in items[:5]:  # Show first 5 items
                    if isinstance(item, dict):
                        resource_name = (item.get('ResourceName') or 
                                       item.get('Name') or
                                       item.get('BucketName') or 
                                       item.get('InstanceId') or 
                                       item.get('DBInstanceIdentifier') or 
                                       item.get('FunctionName') or 
                                       item.get('UserName') or 
                                       item.get('RoleName') or 
                                       item.get('VolumeId') or
                                       item.get('ResourceId') or
                                       'Unknown')
                        issue = item.get('Issue', 'Unknown issue')
                        severity = item.get('severity', item.get('Severity', 'Unknown'))
                        print(f"    • {resource_name}: {issue} [{severity}]")
                
                if len(items) > 5:
                    print(f"    ... and {len(items) - 5} more issues")
            elif isinstance(items, list) and not items:
                print(f"\n📊 Account: {account_id}")
                print(f"  ✅ {method_name}: No issues found")
        
        print(f"\n🎯 Total issues found: {total_issues}")
        
        # Handle output format
        if output_format == 'json':
            # Create standardized output format for dashboard compatibility
            json_output = {
                "scan_timestamp": datetime.now().isoformat(),
                "method": method_name,
                "total_issues": total_issues,
                "results": self._standardize_results_format(results)
            }
            
            filename = self._generate_filename(method_name, results, 'json')
            content = json.dumps(json_output, indent=2, default=str)
            
            if save_to:
                saved_location = await self.storage_manager.save_file(content, filename, save_to, 'json')
                print(f"\n📄 JSON report saved: {saved_location}")
            else:
                with open(filename, 'w') as f:
                    f.write(content)
                print(f"\n📄 JSON report saved: {filename}")
        
        elif output_format == 'csv':
            import csv
            from io import StringIO
            
            filename = self._generate_filename(method_name, results, 'csv')
            
            # Generate CSV content
            csv_content = ""
            if total_issues > 0:
                # Collect all possible fieldnames from all items
                all_fieldnames = set()
                all_items = []
                
                for items in results.values():
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict):
                                all_fieldnames.update(item.keys())
                                all_items.append(item)
                
                if all_items:
                    output = StringIO()
                    fieldnames = sorted(all_fieldnames)
                    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    writer.writerows(all_items)
                    csv_content = output.getvalue()
                    output.close()
            
            if save_to:
                saved_location = await self.storage_manager.save_file(csv_content, filename, save_to, 'csv')
                print(f"\n📊 CSV report saved: {saved_location}")
            else:
                with open(filename, 'w', newline='') as f:
                    f.write(csv_content)
                print(f"\n📊 CSV report saved: {filename}")
    
    async def _execute_single_account(self, method_name: str, *args, **kwargs) -> Dict[str, Any]:
        account_id = self.session.client('sts').get_caller_identity()['Account']
        
        all_results = []
        
        # Filter excluded regions
        filtered_regions = [
            r for r in self.regions
            if not self.config_manager.should_exclude_region(r)
        ]
        
        if len(filtered_regions) < len(self.regions):
            excluded = len(self.regions) - len(filtered_regions)
            print(f"⚠️  {excluded} region(s) excluded by config")
        
        workers_per_region = max(1, self.max_workers // len(filtered_regions)) if filtered_regions else 1
        
        for region in filtered_regions:
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor(max_workers=1) as executor:
                method = getattr(self.service, method_name)
                try:
                    result = await loop.run_in_executor(
                        executor, 
                        lambda r=region: method(self.session, r, max_workers=workers_per_region, config_manager=self.config_manager, *args, **kwargs)
                    )
                except TypeError:
                    result = await loop.run_in_executor(
                        executor, 
                        lambda r=region: method(self.session, r, config_manager=self.config_manager, *args, **kwargs)
                    )
                all_results.extend(result)
        
        return {account_id: all_results}
    
    async def _execute_organization(self, method_name: str, *args, **kwargs) -> Dict[str, Any]:
        accounts = await self._get_organization_accounts()
        print(f"\n🏢 Found {len(accounts)} accounts in organization")
        
        progress = ProgressBar(len(accounts), f"Scanning {method_name} across accounts")
        
        # Process accounts in batches for controlled concurrency
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def execute_with_semaphore(account_id):
            async with semaphore:
                result = await self._execute_for_account(account_id, method_name, *args, **kwargs)
                progress.update()
                return result
        
        tasks = [execute_with_semaphore(account_id) for account_id in accounts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return dict(zip(accounts, results))
    
    async def _get_organization_accounts(self) -> List[str]:
        # If org admin account is specified, assume role there first
        if self.org_admin_account_id:
            sts_client = self.session.client('sts')
            loop = asyncio.get_event_loop()
            
            with ThreadPoolExecutor() as executor:
                assumed_role = await loop.run_in_executor(
                    executor,
                    lambda: sts_client.assume_role(
                        RoleArn=f'arn:aws:iam::{self.org_admin_account_id}:role/{self.cross_account_role}',
                        RoleSessionName='kosty-org-admin'
                    )
                )
            
            org_session = boto3.Session(
                aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_role['Credentials']['SessionToken']
            )
        else:
            org_session = self.session
        
        org_client = org_session.client('organizations')
        
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            def get_all_accounts():
                try:
                    accounts = []
                    paginator = org_client.get_paginator('list_accounts')
                    for page in paginator.paginate():
                        accounts.extend(page['Accounts'])
                    return accounts
                except org_client.exceptions.AWSOrganizationsNotInUseException:
                    raise ValueError("❌ Account is not part of an AWS Organization. Use single account mode instead.")
                except Exception as e:
                    raise ValueError(f"❌ Failed to access organization: {str(e)}")
            
            all_accounts = await loop.run_in_executor(executor, get_all_accounts)
        
        active_accounts = [account['Id'] for account in all_accounts if account['Status'] == 'ACTIVE']
        
        # Filter excluded accounts
        filtered_accounts = [
            acc for acc in active_accounts
            if not self.config_manager.should_exclude_account(acc)
        ]
        
        excluded_count = len(active_accounts) - len(filtered_accounts)
        if excluded_count > 0:
            print(f"⚠️  {excluded_count} account(s) excluded by config")
        
        return filtered_accounts
    
    async def _execute_for_account(self, account_id: str, method_name: str, *args, **kwargs):
        try:
            sts_client = self.session.client('sts')
            
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                assumed_role = await loop.run_in_executor(
                    executor,
                    lambda: sts_client.assume_role(
                        RoleArn=f'arn:aws:iam::{account_id}:role/{self.cross_account_role}',
                        RoleSessionName=f'kosty-{account_id}'
                    )
                )
            
            assumed_session = boto3.Session(
                aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_role['Credentials']['SessionToken']
            )
            
            all_results = []
            workers_per_region = max(1, self.max_workers // len(self.regions))
            
            for region in self.regions:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    method = getattr(self.service, method_name)
                    try:
                        result = await loop.run_in_executor(
                            executor,
                            lambda r=region: method(assumed_session, r, max_workers=workers_per_region, config_manager=self.config_manager, *args, **kwargs)
                        )
                    except TypeError:
                        result = await loop.run_in_executor(
                            executor,
                            lambda r=region: method(assumed_session, r, config_manager=self.config_manager, *args, **kwargs)
                        )
                    all_results.extend(result)
            
            return all_results
            
        except Exception as e:
            return f"Error: {str(e)}"