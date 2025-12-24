import click
import asyncio
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