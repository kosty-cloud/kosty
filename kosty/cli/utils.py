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
    return f

def get_effective_params(ctx, organization, region, max_workers, regions=None):
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
        max_workers or ctx.obj['max_workers']
    )

def execute_service_command(ctx, service_class, method, output, organization, region, max_workers, regions, **kwargs):
    """Execute a service command with common parameters"""
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = service_class()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute(method, output, **kwargs))