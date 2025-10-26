import asyncio
import os
import importlib
from typing import Dict, Any, List, Tuple
from .reporter import CostOptimizationReporter
from .progress import ProgressBar
from .executor import ServiceExecutor

class ComprehensiveScanner:
    def __init__(self, organization: bool, region: str, max_workers: int):
        self.organization = organization
        self.region = region
        self.max_workers = max_workers
        self.reporter = CostOptimizationReporter()
        self.services = self._discover_audit_services()
    
    def _discover_audit_services(self) -> List[Tuple[str, Any]]:
        """Dynamically discover all audit services"""
        services = []
        services_dir = os.path.join(os.path.dirname(__file__), '..', 'services')
        
        for filename in os.listdir(services_dir):
            if filename.endswith('_audit.py') and not filename.startswith('__'):
                module_name = filename[:-3]  # Remove .py
                service_name = module_name.replace('_audit', '')
                
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
        
        return services
    
    async def run_comprehensive_scan(self) -> CostOptimizationReporter:
        """Run all optimization scans and generate report"""
        print("🚀 KOSTY - AWS Cost Optimization Comprehensive Scan")
        print("=" * 60)
        print("🔍 What will be scanned:")
        print("  • Cost optimization opportunities across all services")
        print("  • Security vulnerabilities and misconfigurations")
        print("  • Unused resources and waste identification")
        print("  • Oversized instances and over-provisioned resources")
        print("")
        print(f"📊 Services to scan: {len(self.services)}")
        print(f"🌍 Region: {self.region}")
        print(f"🏢 Scope: {'Organization-wide' if self.organization else 'Single account'}")
        print(f"⚡ Parallel workers: {self.max_workers}")
        print("=" * 60)
        
        progress = ProgressBar(len(self.services), "Comprehensive scan progress")
        
        # Run audit for each service
        for service_name, service_instance in self.services:
            try:
                service_descriptions = {
                    's3': 'S3 buckets (empty, public, unencrypted)',
                    'ec2': 'EC2 instances (stopped, oversized, security)',
                    'rds': 'RDS databases (idle, oversized, public)',
                    'lambda': 'Lambda functions (unused, over-provisioned)',
                    'ebs': 'EBS volumes (orphaned, unencrypted)',
                    'iam': 'IAM users/roles (unused, insecure)',
                    'cloudwatch': 'CloudWatch (unused alarms, expensive logs)',
                    'lb': 'Load Balancers (no targets, underutilized)',
                    'eip': 'Elastic IPs (unattached, on stopped instances)',
                    'nat': 'NAT Gateways (unused, redundant)',
                    'vpc': 'VPC resources (unused security groups)',
                    'cloudfront': 'CloudFront (unused distributions)',
                    'route53': 'Route53 (unused hosted zones)',
                    'elasticache': 'ElastiCache (idle clusters)',
                    'dynamodb': 'DynamoDB (idle tables, over-provisioned)'
                }
                
                desc = service_descriptions.get(service_name, f'{service_name} resources')
                progress.set_description(f"🔍 {service_name.upper()}: {desc}")
                
                executor = ServiceExecutor(service_instance, self.organization, self.region, self.max_workers)
                results = await executor.execute('audit')
                
                # Process results for each account
                for account_id, account_results in results.items():
                    if isinstance(account_results, list):
                        self.reporter.add_results(service_name, 'audit', account_results, account_id)
                    elif isinstance(account_results, str) and account_results.startswith("Error"):
                        print(f"\n    ⚠️  {account_id}: {account_results}")
                    else:
                        self.reporter.add_results(service_name, 'audit', [], account_id)
                        
            except Exception as e:
                print(f"\n    ❌ Error auditing {service_name}: {str(e)}")
            finally:
                progress.update()
        
        print("\n" + "=" * 60)
        print("✅ Comprehensive scan completed!")
        total_issues = sum(sum(cmd['count'] for cmd in svc.values()) for acc in self.reporter.results.values() for svc in acc.values())
        print(f"📊 Total issues found: {total_issues}")
        print(f"💰 Ready to generate cost optimization reports")
        print("=" * 60)
        
        return self.reporter