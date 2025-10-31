import asyncio
import boto3
import json
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
from datetime import datetime
from .progress import ProgressBar, SpinnerProgress

class ServiceExecutor:
    def __init__(self, service, organization: bool, regions: List[str], max_workers: int = 5, cross_account_role: str = 'OrganizationAccountAccessRole', org_admin_account_id: str = None):
        self.service = service
        self.organization = organization
        self.regions = regions
        self.max_workers = max_workers
        self.cross_account_role = cross_account_role
        self.org_admin_account_id = org_admin_account_id
        
    async def execute(self, method_name: str, output_format: str = 'console', *args, **kwargs) -> Dict[str, Any]:
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
            self._display_results(results, method_name, output_format)
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
    
    def _display_results(self, results: Dict[str, Any], method_name: str, output_format: str = 'console'):
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
            json_output = {
                "scan_timestamp": datetime.now().isoformat(),
                "method": method_name,
                "total_issues": total_issues,
                "results": results
            }
            
            filename = f"kosty_audit_{method_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(json_output, f, indent=2, default=str)
            
            print(f"\n📄 JSON report saved: {filename}")
        
        elif output_format == 'csv':
            import csv
            filename = f"kosty_audit_{method_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            
            with open(filename, 'w', newline='') as f:
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
                        fieldnames = sorted(all_fieldnames)
                        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                        writer.writeheader()
                        writer.writerows(all_items)
                        print(f"\n📊 CSV report saved: {filename}")
                    else:
                        print(f"\n📊 CSV report saved: {filename} (no issues found)")
                else:
                    print(f"\n📊 CSV report saved: {filename} (no issues found)")
    
    async def _execute_single_account(self, method_name: str, *args, **kwargs) -> Dict[str, Any]:
        session = boto3.Session()
        account_id = session.client('sts').get_caller_identity()['Account']
        
        all_results = []
        workers_per_region = max(1, self.max_workers // len(self.regions))
        
        for region in self.regions:
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor(max_workers=1) as executor:
                method = getattr(self.service, method_name)
                try:
                    result = await loop.run_in_executor(
                        executor, 
                        lambda r=region: method(session, r, max_workers=workers_per_region, *args, **kwargs)
                    )
                except TypeError:
                    result = await loop.run_in_executor(
                        executor, 
                        lambda r=region: method(session, r, *args, **kwargs)
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
        session = boto3.Session()
        
        # If org admin account is specified, assume role there first
        if self.org_admin_account_id:
            sts_client = session.client('sts')
            loop = asyncio.get_event_loop()
            
            with ThreadPoolExecutor() as executor:
                assumed_role = await loop.run_in_executor(
                    executor,
                    lambda: sts_client.assume_role(
                        RoleArn=f'arn:aws:iam::{self.org_admin_account_id}:role/{self.cross_account_role}',
                        RoleSessionName='kosty-org-admin'
                    )
                )
            
            session = boto3.Session(
                aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_role['Credentials']['SessionToken']
            )
        
        org_client = session.client('organizations')
        
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
        
        return [account['Id'] for account in all_accounts if account['Status'] == 'ACTIVE']
    
    async def _execute_for_account(self, account_id: str, method_name: str, *args, **kwargs):
        try:
            session = boto3.Session()
            sts_client = session.client('sts')
            
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
                            lambda r=region: method(assumed_session, r, max_workers=workers_per_region, *args, **kwargs)
                        )
                    except TypeError:
                        result = await loop.run_in_executor(
                            executor,
                            lambda r=region: method(assumed_session, r, *args, **kwargs)
                        )
                    all_results.extend(result)
            
            return all_results
            
        except Exception as e:
            return f"Error: {str(e)}"