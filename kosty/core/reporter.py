import json
import csv
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path
from .cost_calculator import CostCalculator

class CostOptimizationReporter:
    def __init__(self):
        self.results = {}
        self.scan_timestamp = datetime.now()
        self.organization = False
        self.org_admin_account_id = None
        self.cost_calculator = CostCalculator()
    
    def set_scan_context(self, organization: bool = False, org_admin_account_id: str = None):
        """Set scan context for proper filename generation"""
        self.organization = organization
        self.org_admin_account_id = org_admin_account_id
        
    def add_results(self, service: str, command: str, data: List[Dict[str, Any]], account_id: str = "current"):
        """Add scan results for a service"""
        if account_id not in self.results:
            self.results[account_id] = {}
        
        if service not in self.results[account_id]:
            self.results[account_id][service] = {}
        
        # Add cost information to findings
        enriched_data = [self.cost_calculator.add_cost_to_finding(item) for item in data]
        
        # Calculate total monthly savings
        monthly_savings = sum(item.get('monthly_cost', 0) for item in enriched_data if item.get('monthly_cost') is not None)
            
        self.results[account_id][service][command] = {
            'count': len(enriched_data),
            'items': enriched_data,
            'monthly_savings': round(monthly_savings, 2) if monthly_savings > 0 else 0
        }
    

    
    def generate_summary_report(self) -> str:
        """Generate a summary report"""
        report = []
        report.append("\n" + "=" * 80)
        report.append("KOSTY - AWS AUDIT REPORT")
        report.append("=" * 80)
        report.append(f"Scan Date: {self.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        
        total_issues = sum(sum(cmd['count'] for cmd in svc.values()) for acc in self.results.values() for svc in acc.values())
        total_savings = sum(sum(cmd.get('monthly_savings', 0) for cmd in svc.values()) for acc in self.results.values() for svc in acc.values())
        
        report.append(f"Total Issues: {total_issues}")
        if total_savings > 0:
            report.append(f"Potential Monthly Savings: ${total_savings:,.2f}")
            report.append(f"Potential Annual Savings: ${total_savings * 12:,.2f}")
        report.append("")
        
        for account_id, account_data in self.results.items():
            report.append(f"Account: {account_id}")
            report.append("-" * 50)
            
            account_issues = 0
            account_savings = 0
            
            for service, service_data in account_data.items():
                for command, command_data in service_data.items():
                    count = command_data['count']
                    savings = command_data.get('monthly_savings', 0)
                    
                    if count > 0:
                        if savings > 0:
                            report.append(f"  {service.upper()} {command}: {count} issues (${savings:,.2f}/mo)")
                        else:
                            report.append(f"  {service.upper()} {command}: {count} issues")
                        account_issues += count
                        account_savings += savings
            
            if account_savings > 0:
                report.append(f"  Total: {account_issues} issues, ${account_savings:,.2f}/mo")
            else:
                report.append(f"  Total: {account_issues} issues")
            report.append("")
        
        if total_savings > 0:
            report.append("TOP ISSUES BY SAVINGS")
            report.append("-" * 40)
            
            all_issues = []
            for account_id, account_data in self.results.items():
                for service, service_data in account_data.items():
                    for command, command_data in service_data.items():
                        savings = command_data.get('monthly_savings', 0)
                        if savings > 0:
                            all_issues.append({
                                'service': service,
                                'command': command,
                                'count': command_data['count'],
                                'savings': savings
                            })
            
            all_issues.sort(key=lambda x: x['savings'], reverse=True)
            
            for i, issue in enumerate(all_issues[:10], 1):
                report.append(f"  {i}. {issue['service'].upper()} {issue['command']}: ${issue['savings']:,.2f}/mo ({issue['count']} issues)")
            
            report.append("")
        
        report.append("=" * 80)
        
        return "\n".join(report)
    
    async def save_json_report(self, filename: str = None, organization: bool = False, org_admin_account_id: str = None, save_to: str = None):
        """Save detailed JSON report"""
        from .storage import StorageManager
        
        if not filename:
            timestamp = self.scan_timestamp.strftime('%Y%m%d_%H%M%S')
            
            # Determine scope for filename
            if organization:
                if org_admin_account_id:
                    scope = f"org_{org_admin_account_id}"
                else:
                    scope = "org"
            else:
                # Single account - get first account ID
                account_id = list(self.results.keys())[0] if self.results else "unknown"
                scope = account_id
            
            filename = f"kosty_full_{scope}_{timestamp}.json"
        
        # Standardize results format for dashboard compatibility
        standardized_results = {}
        for account_id, account_data in self.results.items():
            standardized_results[account_id] = []
            for service, service_data in account_data.items():
                for command, command_data in service_data.items():
                    for item in command_data['items']:
                        if isinstance(item, dict):
                            # Ensure required fields for dashboard
                            if 'Service' not in item:
                                item['Service'] = service.upper()
                            if 'AccountId' not in item:
                                item['AccountId'] = account_id
                            standardized_results[account_id].append(item)
        
        report_data = {
            'scan_timestamp': self.scan_timestamp.isoformat(),
            'total_issues': sum(sum(cmd['count'] for cmd in svc.values()) for acc in self.results.values() for svc in acc.values()),
            'results': standardized_results,
            'summary': {
                'total_accounts': len(self.results),
                'total_issues': sum(
                    sum(cmd['count'] for cmd in svc.values())
                    for acc in self.results.values()
                    for svc in acc.values()
                )
            }
        }
        
        content = json.dumps(report_data, indent=2, default=str)
        
        if save_to:
            storage_manager = StorageManager()
            saved_location = await storage_manager.save_file(content, filename, save_to, 'json')
            return saved_location
        else:
            with open(filename, 'w') as f:
                f.write(content)
            return filename
    
    async def save_csv_report(self, filename: str = None, organization: bool = False, org_admin_account_id: str = None, save_to: str = None):
        """Save CSV report for spreadsheet analysis"""
        from .storage import StorageManager
        from io import StringIO
        
        if not filename:
            timestamp = self.scan_timestamp.strftime('%Y%m%d_%H%M%S')
            
            # Determine scope for filename
            if organization:
                if org_admin_account_id:
                    scope = f"org_{org_admin_account_id}"
                else:
                    scope = "org"
            else:
                # Single account - get first account ID
                account_id = list(self.results.keys())[0] if self.results else "unknown"
                scope = account_id
            
            filename = f"kosty_full_{scope}_{timestamp}.csv"
        
        # Generate CSV content
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Account', 'Service', 'Command', 'Resource Count', 'Monthly Cost (USD)', 'Annual Cost (USD)', 'Details'])
        
        for account_id, account_data in self.results.items():
            for service, service_data in account_data.items():
                for command, command_data in service_data.items():
                    if command_data['count'] > 0:
                        details = '; '.join([
                            f"{item.get('InstanceId', item.get('VolumeId', item.get('FunctionName', item.get('ClusterName', item.get('resource_id', 'Resource')))))}"
                            for item in command_data['items'][:5]  # First 5 items
                        ])
                        
                        monthly_savings = command_data.get('monthly_savings', 0)
                        annual_savings = monthly_savings * 12 if monthly_savings > 0 else 0
                        
                        writer.writerow([
                            account_id,
                            service,
                            command,
                            command_data['count'],
                            f"${monthly_savings:,.2f}" if monthly_savings > 0 else "N/A",
                            f"${annual_savings:,.2f}" if annual_savings > 0 else "N/A",
                            details
                        ])
        
        csv_content = output.getvalue()
        output.close()
        
        if save_to:
            storage_manager = StorageManager()
            saved_location = await storage_manager.save_file(csv_content, filename, save_to, 'csv')
            return saved_location
        else:
            with open(filename, 'w', newline='') as f:
                f.write(csv_content)
            return filename