import asyncio
import boto3
import json
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
from datetime import datetime
from .progress import ProgressBar, SpinnerProgress

class ServiceExecutor:
    def __init__(self, service, organization: bool, region: str, max_workers: int = 5):
        self.service = service
        self.organization = organization
        self.region = region
        self.max_workers = max_workers
        
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
        region_info = f'📍 Region: {self.region}' if self.region else '🌍 All regions'
        
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
                                       item.get('BucketName') or 
                                       item.get('InstanceId') or 
                                       item.get('DBInstanceIdentifier') or 
                                       item.get('FunctionName') or 
                                       item.get('UserName') or 
                                       item.get('RoleName') or 
                                       'Unknown')
                        issue = item.get('Issue', 'Unknown issue')
                        severity = item.get('Severity', 'Unknown')
                        print(f"    • {resource_name}: {issue} [{severity}]")
                
                if len(items) > 5:
                    print(f"    ... and {len(items) - 5} more issues")
        
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
                    # Get first item to determine fieldnames
                    first_item = None
                    for items in results.values():
                        if isinstance(items, list) and items:
                            first_item = items[0]
                            break
                    
                    if first_item:
                        fieldnames = first_item.keys()
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        
                        for items in results.values():
                            if isinstance(items, list):
                                writer.writerows(items)
            
            print(f"\n📊 CSV report saved: {filename}")
    
    async def _execute_single_account(self, method_name: str, *args, **kwargs) -> Dict[str, Any]:
        session = boto3.Session()
        account_id = session.client('sts').get_caller_identity()['Account']
        
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as executor:  # Single thread for service execution
            method = getattr(self.service, method_name)
            # Pass max_workers to service method if it accepts it
            try:
                result = await loop.run_in_executor(
                    executor, 
                    lambda: method(session, self.region, max_workers=self.max_workers, *args, **kwargs)
                )
            except TypeError:
                # Fallback for services that don't accept max_workers
                result = await loop.run_in_executor(
                    executor, 
                    lambda: method(session, self.region, *args, **kwargs)
                )
        
        return {account_id: result}
    
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
        org_client = session.client('organizations')
        
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            response = await loop.run_in_executor(
                executor,
                org_client.list_accounts
            )
        
        return [acc['Id'] for acc in response['Accounts'] if acc['Status'] == 'ACTIVE']
    
    async def _execute_for_account(self, account_id: str, method_name: str, *args, **kwargs):
        try:
            session = boto3.Session()
            sts_client = session.client('sts')
            
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                assumed_role = await loop.run_in_executor(
                    executor,
                    lambda: sts_client.assume_role(
                        RoleArn=f'arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole',
                        RoleSessionName=f'kosty-{account_id}'
                    )
                )
            
            assumed_session = boto3.Session(
                aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_role['Credentials']['SessionToken']
            )
            
            with ThreadPoolExecutor(max_workers=1) as executor:  # Single thread for service execution
                method = getattr(self.service, method_name)
                # Pass max_workers to service method if it accepts it
                try:
                    result = await loop.run_in_executor(
                        executor,
                        lambda: method(assumed_session, self.region, max_workers=self.max_workers, *args, **kwargs)
                    )
                except TypeError:
                    # Fallback for services that don't accept max_workers
                    result = await loop.run_in_executor(
                        executor,
                        lambda: method(assumed_session, self.region, *args, **kwargs)
                    )
            
            return result
            
        except Exception as e:
            return f"Error: {str(e)}"