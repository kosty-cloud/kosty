import json
import csv
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

class CostOptimizationReporter:
    def __init__(self):
        self.results = {}
        self.scan_timestamp = datetime.now()
        
    def add_results(self, service: str, command: str, data: List[Dict[str, Any]], account_id: str = "current"):
        """Add scan results for a service"""
        if account_id not in self.results:
            self.results[account_id] = {}
        
        if service not in self.results[account_id]:
            self.results[account_id][service] = {}
            
        self.results[account_id][service][command] = {
            'count': len(data),
            'items': data,
            'potential_savings': self._calculate_savings(service, command, data)
        }
        
        # No cost calculation
    
    def _calculate_savings(self, service: str, command: str, data: List[Dict[str, Any]]) -> int:
        """No cost calculation - just count issues"""
        return len(data)
    

    
    def generate_summary_report(self) -> str:
        """Generate a summary report"""
        report = []
        report.append("\n" + "=" * 80)
        report.append("🏆 KOSTY - AWS COST OPTIMIZATION REPORT")
        report.append("=" * 80)
        report.append(f"📅 Scan Date: {self.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"📊 Total Issues Found: {sum(sum(cmd['count'] for cmd in svc.values()) for acc in self.results.values() for svc in acc.values())}")
        report.append("")
        
        # Summary by account
        for account_id, account_data in self.results.items():
            report.append(f"📊 Account: {account_id}")
            report.append("-" * 50)
            
            account_issues = 0
            total_issues = 0
            
            for service, service_data in account_data.items():
                for command, command_data in service_data.items():
                    count = command_data['count']
                    savings = command_data['potential_savings']
                    
                    if count > 0:
                        report.append(f"  🔍 {service.upper()} {command}: {count} issues")
                        account_issues += count
                        total_issues += count
            
            report.append(f"  💡 Account Total: {account_issues} issues found")
            report.append("")
        
        # Top issues by count
        report.append("🎯 TOP ISSUES BY COUNT")
        report.append("-" * 30)
        
        all_issues = []
        for account_id, account_data in self.results.items():
            for service, service_data in account_data.items():
                for command, command_data in service_data.items():
                    if command_data['count'] > 0:
                        all_issues.append({
                            'service': service,
                            'command': command,
                            'count': command_data['count']
                        })
        
        # Sort by issue count
        all_issues.sort(key=lambda x: x['count'], reverse=True)
        
        for i, issue in enumerate(all_issues[:10], 1):
            report.append(f"  {i:2d}. {issue['service'].upper()} {issue['command']}: {issue['count']} issues")
        
        report.append("")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def save_json_report(self, filename: str = None):
        """Save detailed JSON report"""
        if not filename:
            filename = f"kosty-report-{self.scan_timestamp.strftime('%Y%m%d-%H%M%S')}.json"
        
        report_data = {
            'scan_timestamp': self.scan_timestamp.isoformat(),
            'total_issues': sum(sum(cmd['count'] for cmd in svc.values()) for acc in self.results.values() for svc in acc.values()),
            'results': self.results,
            'summary': {
                'total_accounts': len(self.results),
                'total_issues': sum(
                    sum(cmd['count'] for cmd in svc.values())
                    for acc in self.results.values()
                    for svc in acc.values()
                )
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return filename
    
    def save_csv_report(self, filename: str = None):
        """Save CSV report for spreadsheet analysis"""
        if not filename:
            filename = f"kosty-report-{self.scan_timestamp.strftime('%Y%m%d-%H%M%S')}.csv"
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Account', 'Service', 'Command', 'Resource Count', 'Cost Estimate', 'Details'])
            
            for account_id, account_data in self.results.items():
                for service, service_data in account_data.items():
                    for command, command_data in service_data.items():
                        if command_data['count'] > 0:
                            details = '; '.join([
                                f"{item.get('InstanceId', item.get('VolumeId', item.get('FunctionName', item.get('ClusterName', 'Resource'))))}"
                                for item in command_data['items'][:5]  # First 5 items
                            ])
                            
                            writer.writerow([
                                account_id,
                                service,
                                command,
                                command_data['count'],
                                'N/A',  # No cost calculation
                                details
                            ])
        
        return filename