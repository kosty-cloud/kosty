import click
import asyncio
import json
import os
from datetime import datetime
from ..core.executor import ServiceExecutor
from ..core.config import ConfigManager

def common_options(f):
    """Decorator to add common options to all service commands"""
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

def get_profile_from_context(ctx, profile_arg):
    """Get profile from command arg or context"""
    return profile_arg or ctx.obj.get('profile', 'default')

def get_effective_params(ctx, organization, region, max_workers, regions=None, cross_account_role=None, org_admin_account_id=None):
    """Get effective parameters, preferring command-level over global"""
    # Priority: regions > region > global region
    effective_regions = None
    if regions:
        effective_regions = [r.strip() for r in regions.split(',')]
    elif region:
        effective_regions = [region]
    elif ctx.obj['region']:
        effective_regions = [ctx.obj['region']]
    else:
        effective_regions = ['us-east-1']
    
    return (
        organization or ctx.obj['organization'],
        effective_regions,
        max_workers or ctx.obj['max_workers'],
        cross_account_role or 'OrganizationAccountAccessRole',
        org_admin_account_id
    )

def execute_service_command(ctx, service_class, method, output, organization, region, max_workers, regions, cross_account_role=None, org_admin_account_id=None, save_to=None, profile=None, **kwargs):
    """Execute a service command with common parameters"""
    profile_name = get_profile_from_context(ctx, profile)
    
    try:
        config_manager = ConfigManager(
            config_file=ctx.obj.get('config_file'),
            profile=profile_name
        )
        session = config_manager.get_aws_session()
        
        # Merge config with CLI args (CLI takes priority)
        final_config = config_manager.merge_with_cli_args({
            'organization': organization,
            'region': region,
            'regions': regions,
            'max_workers': max_workers,
            'cross_account_role': cross_account_role,
            'org_admin_account_id': org_admin_account_id
        })
        
        # Handle regions priority
        if final_config.get('regions'):
            if isinstance(final_config['regions'], str):
                reg_list = [r.strip() for r in final_config['regions'].split(',')]
            else:
                reg_list = final_config['regions']
        elif final_config.get('region'):
            reg_list = [final_config['region']]
        else:
            reg_list = ['us-east-1']
        
        org = final_config.get('organization', False)
        workers = final_config.get('max_workers', 10)
        role_name = final_config.get('cross_account_role', 'OrganizationAccountAccessRole')
        admin_account = final_config.get('org_admin_account_id')
        
    except Exception:
        config_manager = None
        session = None
        org, reg_list, workers, role_name, admin_account = get_effective_params(ctx, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)
    
    service = service_class()
    executor = ServiceExecutor(service, org, reg_list, workers, role_name, admin_account, config_manager=config_manager, session=session)
    asyncio.run(executor.execute(method, output, save_to=save_to, **kwargs))


def execute_engine_command(ctx, service_name, method, output, organization, region, max_workers, regions, cross_account_role=None, org_admin_account_id=None, save_to=None, profile=None, check_id=None, **kwargs):
    """Execute a service command via the plugin engine."""
    import boto3
    from ..core.registry import registry
    from ..core.models import FindingType

    profile_name = get_profile_from_context(ctx, profile)

    try:
        config_manager = ConfigManager(
            config_file=ctx.obj.get('config_file'),
            profile=profile_name
        )
        session = config_manager.get_aws_session()
        final_config = config_manager.merge_with_cli_args({
            'organization': organization, 'region': region, 'regions': regions,
            'max_workers': max_workers, 'cross_account_role': cross_account_role,
            'org_admin_account_id': org_admin_account_id
        })
        if final_config.get('regions'):
            reg_list = [r.strip() for r in final_config['regions'].split(',')] if isinstance(final_config['regions'], str) else final_config['regions']
        elif final_config.get('region'):
            reg_list = [final_config['region']]
        else:
            reg_list = ['us-east-1']
        workers = final_config.get('max_workers', 10)
    except Exception:
        config_manager = None
        session = None
        _, reg_list, workers, _, _ = get_effective_params(ctx, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

    if session is None:
        session = boto3.Session()

    # Ensure plugins are loaded
    _ensure_plugins_loaded()

    # Get checks to run
    if check_id:
        # Single check by ID
        entry = registry.get_check(check_id)
        checks = [entry] if entry else []
    else:
        # All checks for service, optionally filtered by type
        checks = registry.get_checks_by_service(service_name)
        if method == 'cost_audit':
            checks = [c for c in checks if c['metadata'].finding_type == FindingType.COST]
        elif method == 'security_audit':
            checks = [c for c in checks if c['metadata'].finding_type == FindingType.SECURITY]

    # Filter deep checks
    deep = kwargs.get('deep', False)
    if not deep:
        checks = [c for c in checks if not c['metadata'].requires_deep]

    # Run checks
    from concurrent.futures import ThreadPoolExecutor, as_completed

    all_findings = []
    for rgn in reg_list:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {}
            for check in checks:
                future = executor.submit(
                    check['func'], session=session, region=rgn,
                    config_manager=config_manager, **kwargs
                )
                futures[future] = check['metadata'].check_id

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if isinstance(result, list):
                        # Inject compliance_ids from metadata
                        check_entry = next((c for c in checks if futures[future] == c['metadata'].check_id), None)
                        if check_entry and check_entry['metadata'].compliance_ids:
                            for f in result:
                                if hasattr(f, 'compliance_ids') and not f.compliance_ids:
                                    f.compliance_ids = check_entry['metadata'].compliance_ids
                        all_findings.extend(result)
                except Exception:
                    pass

    # Output
    _output_findings(all_findings, service_name, output, save_to)


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