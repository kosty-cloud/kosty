"""Shared utilities for all CLI service commands.

The key entry point here is execute_engine_command(), which every service
command calls. It handles config resolution, plugin loading, check selection,
execution, and output in one place so individual command files stay thin.
"""

import click
import json
import os
from datetime import datetime
from ..core.config import ConfigManager


def common_options(f):
    """Decorator that attaches the standard scan options to any Click command.

    Applied to every service command so the option set stays consistent
    across all 30+ commands without repeating the definitions.
    """
    f = click.option('--profile', help='Configuration profile to use')(f)
    f = click.option('--output', default='console', type=click.Choice(['console', 'json', 'csv']), help='Output format')(f)
    f = click.option('--save-to', help='Save output to S3 (s3://bucket/path) or local path (/path/to/file)')(f)
    f = click.option('--regions', help='Comma-separated list of regions (e.g., us-east-1,eu-west-1)')(f)
    f = click.option('--max-workers', default=10, help='Maximum number of worker threads')(f)
    f = click.option('--region', help='AWS region to scan')(f)
    f = click.option('--organization', is_flag=True, help='Scan entire AWS organization')(f)
    f = click.option('--cross-account-role', default='OrganizationAccountAccessRole', help='Role name for cross-account access')(f)
    f = click.option('--org-admin-account-id', help='Organization admin account ID (if different from current account)')(f)
    return f

def _resolve_scan_params(ctx, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id):
    """Resolve session, region list, and worker count from CLI args + config.

    Config file values are the baseline; CLI args take priority.
    Falls back to a plain boto3.Session() with the CLI-provided region
    if config loading fails (e.g. malformed kosty.yaml).
    """
    import boto3
    profile_name = profile or ctx.obj.get('profile', 'default')
    try:
        config_manager = ConfigManager(
            config_file=ctx.obj.get('config_file'),
            profile=profile_name
        )
        session = config_manager.get_aws_session()
        final = config_manager.merge_with_cli_args({
            'organization': organization, 'region': region, 'regions': regions,
            'max_workers': max_workers, 'cross_account_role': cross_account_role,
            'org_admin_account_id': org_admin_account_id
        })
        if final.get('regions'):
            reg_list = [r.strip() for r in final['regions'].split(',')] if isinstance(final['regions'], str) else final['regions']
        elif final.get('region'):
            reg_list = [final['region']]
        else:
            reg_list = ['us-east-1']
        return session, reg_list, final.get('max_workers', 10), config_manager
    except Exception:
        if regions:
            reg_list = [r.strip() for r in regions.split(',')]
        elif region:
            reg_list = [region]
        elif ctx.obj.get('region'):
            reg_list = [ctx.obj['region']]
        else:
            reg_list = ['us-east-1']
        return boto3.Session(), reg_list, max_workers or ctx.obj.get('max_workers', 10), None


def _run_checks(checks, session, reg_list, workers, config_manager, **kwargs):
    """Execute a list of checks across regions and return all findings.

    Injects compliance_ids from check metadata into each finding so plugins
    don't need to repeat the mapping in their Finding constructors.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    all_findings = []
    for rgn in reg_list:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(c['func'], session=session, region=rgn,
                                config_manager=config_manager, **kwargs): c
                for c in checks
            }
            for future in as_completed(futures):
                check = futures[future]
                try:
                    result = future.result()
                    if isinstance(result, list):
                        if check['metadata'].compliance_ids:
                            for f in result:
                                if hasattr(f, 'compliance_ids') and not f.compliance_ids:
                                    f.compliance_ids = check['metadata'].compliance_ids
                        all_findings.extend(result)
                except Exception:
                    pass
    return all_findings


def execute_engine_command(ctx, service_name, method, output, organization, region,
                           max_workers, regions, cross_account_role=None,
                           org_admin_account_id=None, save_to=None, profile=None,
                           check_id=None, **kwargs):
    """Resolve config, select checks, run them, and display results."""
    from ..core.registry import registry
    from ..core.models import FindingType

    session, reg_list, workers, config_manager = _resolve_scan_params(
        ctx, profile, organization, region, max_workers, regions,
        cross_account_role, org_admin_account_id
    )

    _ensure_plugins_loaded()

    if check_id:
        entry = registry.get_check(check_id)
        checks = [entry] if entry else []
    else:
        checks = registry.get_checks_by_service(service_name)
        if method == 'cost_audit':
            checks = [c for c in checks if c['metadata'].finding_type == FindingType.COST]
        elif method == 'security_audit':
            checks = [c for c in checks if c['metadata'].finding_type == FindingType.SECURITY]

    deep = kwargs.get('deep', False)
    if not deep:
        checks = [c for c in checks if not c['metadata'].requires_deep]

    findings = _run_checks(checks, session, reg_list, workers, config_manager, **kwargs)
    _output_findings(findings, service_name, output, save_to)


def _ensure_plugins_loaded():
    """Load native plugins if not already loaded."""
    from ..core.registry import registry
    if registry.count > 0:
        return
    from ..core.loader import PluginLoader
    loader = PluginLoader()
    plugins_dir = os.path.join(os.path.dirname(__file__), '..', 'providers', 'aws', 'services')
    plugins_dir = os.path.abspath(plugins_dir)
    if os.path.isdir(plugins_dir):
        loader.load_directory(plugins_dir)


def _output_findings(findings, service_name, output, save_to=None):
    """Display findings in the requested format."""
    items = [f.to_dict() for f in findings]
    total = len(items)

    if output == 'console' or output == 'all':
        if total == 0:
            print(f"\n✅ {service_name.upper()}: No issues found")
        else:
            print(f"\n🔍 {service_name.upper()}: {total} issues found")
            print("─" * 50)
            for item in items:
                sev_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}.get(item.get('severity', ''), '⚪')
                print(f"  {sev_icon} [{item.get('severity', '').upper()}] {item.get('Issue', '')}")
                print(f"     Resource: {item.get('ResourceId', '')} ({item.get('Region', '')})")
                if item.get('Risk'):
                    print(f"     Risk: {item['Risk']}")

    if output in ['json', 'all']:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        account_id = items[0].get('AccountId', 'unknown') if items else 'unknown'
        filename = f"kosty_{service_name}_{account_id}_{timestamp}.json"
        if save_to:
            os.makedirs(save_to, exist_ok=True)
            filename = os.path.join(save_to, filename)
        report = {'scan_timestamp': datetime.now().isoformat(), 'service': service_name, 'total_issues': total, 'results': items}
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n📄 JSON report saved: {filename}")

    if output in ['csv', 'all']:
        import csv
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        account_id = items[0].get('AccountId', 'unknown') if items else 'unknown'
        filename = f"kosty_{service_name}_{account_id}_{timestamp}.csv"
        if save_to:
            os.makedirs(save_to, exist_ok=True)
            filename = os.path.join(save_to, filename)
        if items:
            fieldnames = sorted(set().union(*(item.keys() for item in items)))
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(items)
            print(f"📊 CSV report saved: {filename}")