"""Audit report generation for Kosty scan results.

Handles three output formats:
- Console summary (generate_summary_report)
- JSON for the web dashboard (save_json_report)
- CSV for spreadsheet analysis (save_csv_report)

The reporter is intentionally dumb about how findings are produced —
it just aggregates whatever the engine feeds it via add_results().
"""

import asyncio
import json
import csv
from datetime import datetime
from io import StringIO
from typing import Dict, List, Any


class CostOptimizationReporter:
    """Collects scan findings and renders them into human-readable reports.

    Findings flow in via add_results() after the engine completes each
    service scan. The reporter groups them by account → service → command
    and computes per-group savings totals for the summary view.
    """

    def __init__(self):
        self.results: Dict[str, Any] = {}
        self.scan_timestamp = datetime.now()
        self.organization = False
        self.org_admin_account_id = None

    def set_scan_context(self, organization: bool = False, org_admin_account_id: str = None):
        """Store org context so filenames reflect the scan scope."""
        self.organization = organization
        self.org_admin_account_id = org_admin_account_id

    def add_results(self, service: str, command: str, data: List[Dict[str, Any]], account_id: str = "current"):
        """Ingest findings for one service/command pair.

        monthly_savings is read directly from each finding — plugins set it
        on the Finding object, and it survives serialization via to_dict().
        """
        if account_id not in self.results:
            self.results[account_id] = {}
        if service not in self.results[account_id]:
            self.results[account_id][service] = {}

        monthly_savings = sum(item.get('monthly_savings', 0) for item in data)

        self.results[account_id][service][command] = {
            'count': len(data),
            'items': data,
            'monthly_savings': round(monthly_savings, 2) if monthly_savings > 0 else 0,
        }

    def generate_summary_report(self) -> str:
        """Build the console summary printed at the end of every scan.

        Shows totals, per-account breakdown, top cost savings, and the
        worst critical/high security findings — deduplicated by issue text
        so you don't see the same finding listed 50 times for 50 resources.
        """
        report = []
        report.append("\n" + "=" * 80)
        report.append("KOSTY - AWS AUDIT REPORT")
        report.append("=" * 80)
        report.append(f"Scan Date: {self.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")

        total_issues = sum(
            sum(cmd['count'] for cmd in svc.values())
            for acc in self.results.values()
            for svc in acc.values()
        )
        total_savings = sum(
            sum(cmd.get('monthly_savings', 0) for cmd in svc.values())
            for acc in self.results.values()
            for svc in acc.values()
        )

        total_cost = 0
        total_security = 0
        for acc in self.results.values():
            for svc in acc.values():
                for cmd_data in svc.values():
                    for item in cmd_data.get('items', []):
                        if (item.get('type') or item.get('Type') or '').lower() == 'cost':
                            total_cost += 1
                        else:
                            total_security += 1

        report.append(f"Total Issues: {total_issues} (🔐 {total_security} security, 💰 {total_cost} cost)")
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
            report.append("💰 TOP COST SAVINGS")
            report.append("-" * 40)

            cost_items = []
            for account_data in self.results.values():
                for service, service_data in account_data.items():
                    for command, command_data in service_data.items():
                        savings = command_data.get('monthly_savings', 0)
                        if savings > 0:
                            cost_items.append({
                                'service': service,
                                'command': command,
                                'count': command_data['count'],
                                'savings': savings,
                            })

            cost_items.sort(key=lambda x: x['savings'], reverse=True)
            for i, item in enumerate(cost_items[:10], 1):
                report.append(f"  {i}. {item['service'].upper()} {item['command']}: ${item['savings']:,.2f}/mo ({item['count']} issues)")
            report.append("")

        # Deduplicate security findings by (service, issue text) so a finding
        # affecting 50 resources shows as one line with a count, not 50 lines.
        security_by_issue = {}
        for account_data in self.results.values():
            for service, service_data in account_data.items():
                for command_data in service_data.values():
                    for item in command_data.get('items', []):
                        item_type = (item.get('type') or item.get('Type') or '').lower()
                        severity = (item.get('severity') or item.get('Severity') or '').lower()
                        if item_type != 'cost' and severity in ('critical', 'high'):
                            issue_text = item.get('Issue', '')
                            key = f"{service.upper()}:{issue_text}"
                            if key not in security_by_issue:
                                security_by_issue[key] = {
                                    'service': service.upper(),
                                    'issue': issue_text,
                                    'severity': severity,
                                    'count': 0,
                                    'resource': item.get('ResourceId') or item.get('ResourceName', ''),
                                }
                            security_by_issue[key]['count'] += 1

        if security_by_issue:
            report.append("🔐 TOP SECURITY FINDINGS")
            report.append("-" * 40)
            sorted_findings = sorted(
                security_by_issue.values(),
                key=lambda x: (0 if x['severity'] == 'critical' else 1, -x['count'])
            )
            for f in sorted_findings[:10]:
                icon = '🔴' if f['severity'] == 'critical' else '🟠'
                if f['count'] > 1:
                    report.append(f"  {icon} {f['service']}: {f['issue']} ({f['count']} resources)")
                else:
                    report.append(f"  {icon} {f['service']}: {f['issue']} — {f['resource']}")
            remaining = len(sorted_findings) - min(10, len(sorted_findings))
            if remaining > 0:
                report.append(f"  ... and {remaining} more critical/high finding types")
            report.append("")

        report.append("=" * 80)
        return "\n".join(report)

    def save_json_report(self, filename: str = None, organization: bool = False,
                         org_admin_account_id: str = None, save_to: str = None) -> str:
        """Write findings to a JSON file consumable by the web dashboard.

        The dashboard expects a flat list of finding dicts per account, so we
        flatten the account → service → command nesting here. Service and
        AccountId are injected if a plugin forgot to set them (shouldn't happen
        in practice, but defensive is better than a broken dashboard).
        """
        from .storage import StorageManager

        if not filename:
            timestamp = self.scan_timestamp.strftime('%Y%m%d_%H%M%S')
            if organization:
                scope = f"org_{org_admin_account_id}" if org_admin_account_id else "org"
            else:
                scope = list(self.results.keys())[0] if self.results else "unknown"
            filename = f"kosty_full_{scope}_{timestamp}.json"

        standardized_results = {}
        for account_id, account_data in self.results.items():
            standardized_results[account_id] = []
            for service, service_data in account_data.items():
                for command_data in service_data.values():
                    for item in command_data['items']:
                        if isinstance(item, dict):
                            item.setdefault('Service', service.upper())
                            item.setdefault('AccountId', account_id)
                            standardized_results[account_id].append(item)

        total = sum(
            sum(cmd['count'] for cmd in svc.values())
            for acc in self.results.values()
            for svc in acc.values()
        )
        report_data = {
            'scan_timestamp': self.scan_timestamp.isoformat(),
            'total_issues': total,
            'results': standardized_results,
            'summary': {
                'total_accounts': len(self.results),
                'total_issues': total,
            },
        }

        content = json.dumps(report_data, indent=2, default=str)

        if save_to:
            return asyncio.run(StorageManager().save_file(content, filename, save_to, 'json'))

        with open(filename, 'w') as f:
            f.write(content)
        return filename

    def save_csv_report(self, filename: str = None, organization: bool = False,
                        org_admin_account_id: str = None, save_to: str = None) -> str:
        """Write a summary CSV — one row per service/command, not per finding.

        Intentionally coarse-grained: the CSV is meant for a quick spreadsheet
        overview, not a full finding dump. Use the JSON report for that.
        """
        from .storage import StorageManager

        if not filename:
            timestamp = self.scan_timestamp.strftime('%Y%m%d_%H%M%S')
            if organization:
                scope = f"org_{org_admin_account_id}" if org_admin_account_id else "org"
            else:
                scope = list(self.results.keys())[0] if self.results else "unknown"
            filename = f"kosty_full_{scope}_{timestamp}.csv"

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Account', 'Service', 'Command', 'Resource Count',
                         'Monthly Cost (USD)', 'Annual Cost (USD)', 'Details'])

        for account_id, account_data in self.results.items():
            for service, service_data in account_data.items():
                for command, command_data in service_data.items():
                    if command_data['count'] == 0:
                        continue
                    # First 5 resource IDs as a quick reference in the spreadsheet
                    details = '; '.join(
                        item.get('ResourceId') or item.get('resource_id', 'unknown')
                        for item in command_data['items'][:5]
                    )
                    monthly = command_data.get('monthly_savings', 0)
                    annual = monthly * 12 if monthly > 0 else 0
                    writer.writerow([
                        account_id, service, command, command_data['count'],
                        f"${monthly:,.2f}" if monthly > 0 else "N/A",
                        f"${annual:,.2f}" if annual > 0 else "N/A",
                        details,
                    ])

        csv_content = output.getvalue()
        output.close()

        if save_to:
            return asyncio.run(StorageManager().save_file(csv_content, filename, save_to, 'csv'))

        with open(filename, 'w', newline='') as f:
            f.write(csv_content)
        return filename
