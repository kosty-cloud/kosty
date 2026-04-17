import click
from .utils import common_options, execute_service_command


@click.group()
@click.pass_context
def elasticache(ctx):
    """ElastiCache operations"""
    pass


@elasticache.command('audit')
@common_options
@click.pass_context
def elasticache_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run ElastiCache audit"""
    from ..services.elasticache_audit import ElastiCacheAuditService
    execute_service_command(ctx, ElastiCacheAuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@elasticache.command('security-audit')
@common_options
@click.pass_context
def elasticache_security(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run ElastiCache security audit"""
    from ..services.elasticache_audit import ElastiCacheAuditService
    execute_service_command(ctx, ElastiCacheAuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@elasticache.command('check-no-encryption-at-rest')
@common_options
@click.pass_context
def elasticache_check_rest(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find clusters without encryption at rest"""
    from ..services.elasticache_audit import ElastiCacheAuditService
    execute_service_command(ctx, ElastiCacheAuditService, 'check_no_encryption_at_rest', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@elasticache.command('check-no-encryption-in-transit')
@common_options
@click.pass_context
def elasticache_check_transit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find clusters without encryption in transit"""
    from ..services.elasticache_audit import ElastiCacheAuditService
    execute_service_command(ctx, ElastiCacheAuditService, 'check_no_encryption_in_transit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)
