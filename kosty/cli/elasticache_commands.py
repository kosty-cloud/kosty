import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def elasticache(ctx):
    """ElastiCache operations"""
    pass

@elasticache.command('audit')
@common_options
@click.pass_context
def elasticache_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run ElastiCache complete audit"""
    execute_engine_command(ctx, 'ElastiCache', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@elasticache.command('cost-audit')
@common_options
@click.pass_context
def elasticache_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run ElastiCache cost optimization audit"""
    execute_engine_command(ctx, 'ElastiCache', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@elasticache.command('security-audit')
@common_options
@click.pass_context
def elasticache_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run ElastiCache security audit"""
    execute_engine_command(ctx, 'ElastiCache', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@elasticache.command('check-no-encryption-at-rest')
@common_options
@click.pass_context
def elasticache_check_no_encryption_at_rest(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find clusters without encryption at rest"""
    execute_engine_command(ctx, 'ElastiCache', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-elasticache-001')

@elasticache.command('check-no-encryption-in-transit')
@common_options
@click.pass_context
def elasticache_check_no_encryption_in_transit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find clusters without encryption in transit"""
    execute_engine_command(ctx, 'ElastiCache', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-elasticache-002')

