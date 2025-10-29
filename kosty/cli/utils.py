import click
import asyncio
from ..core.executor import ServiceExecutor

def common_options(f):
    """Decorator to add common options to all service commands"""
    f = click.option('--output', default='console', type=click.Choice(['console', 'json', 'csv']), help='Output format')(f)
    f = click.option('--regions', help='Comma-separated list of regions (e.g., us-east-1,eu-west-1)')(f)
    f = click.option('--max-workers', default=10, help='Maximum number of worker threads')(f)
    f = click.option('--region', help='AWS region to scan')(f)
    f = click.option('--organization', is_flag=True, help='Scan entire AWS organization')(f)
    f = click.option('--cross-account-role', default='OrganizationAccountAccessRole', help='Role name for cross-account access')(f)
    f = click.option('--org-admin-account-id', help='Organization admin account ID (if different from current account)')(f)
    return f

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

def execute_service_command(ctx, service_class, method, output, organization, region, max_workers, regions, cross_account_role=None, org_admin_account_id=None, **kwargs):
    """Execute a service command with common parameters"""
    org, reg_list, workers, role_name, admin_account = get_effective_params(ctx, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)
    service = service_class()
    executor = ServiceExecutor(service, org, reg_list, workers, role_name, admin_account)
    asyncio.run(executor.execute(method, output, **kwargs))