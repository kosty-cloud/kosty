import click
from .utils import common_options, execute_engine_command


@click.command('public-exposure')
@common_options
@click.pass_context
def public_exposure(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """🌐 External attack surface audit — find all publicly exposed resources and evaluate protections"""
    execute_engine_command(ctx, 'PublicExposure', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-exposure-001')
