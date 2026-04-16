import click
from .utils import common_options, execute_service_command


@click.command('public-exposure')
@common_options
@click.pass_context
def public_exposure(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """🌐 External attack surface audit — find all publicly exposed resources and evaluate protections"""
    from ..services.public_exposure import PublicExposureService
    execute_service_command(ctx, PublicExposureService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
