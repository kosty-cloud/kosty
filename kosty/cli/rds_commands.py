import click
from .utils import common_options, execute_engine_command

@click.group()
@click.pass_context
def rds(ctx):
    """RDS operations"""
    pass

@rds.command('audit')
@common_options
@click.pass_context
def rds_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run RDS complete audit"""
    execute_engine_command(ctx, 'RDS', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@rds.command('cost-audit')
@common_options
@click.pass_context
def rds_cost_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run RDS cost optimization audit"""
    execute_engine_command(ctx, 'RDS', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@rds.command('security-audit')
@common_options
@click.pass_context
def rds_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run RDS security audit"""
    execute_engine_command(ctx, 'RDS', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)

@rds.command('check-idle-instances')
@click.option('--days', default=14, help='Days to analyze')
@common_options
@click.pass_context
def rds_check_idle_instances(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find idle RDS instances"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-001', days=days)

@rds.command('check-oversized-instances')
@click.option('--days', default=14, help='Days to analyze')
@common_options
@click.pass_context
def rds_check_oversized_instances(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find oversized RDS instances"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-002', days=days)

@rds.command('check-unused-replicas')
@common_options
@click.pass_context
def rds_check_unused_replicas(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unused read replicas"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-003')

@rds.command('check-multi-az-dev')
@common_options
@click.pass_context
def rds_check_multi_az_dev(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find Multi-AZ on dev/test"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-004')

@rds.command('check-gp2-storage')
@common_options
@click.pass_context
def rds_check_gp2_storage(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find gp2 storage (should be gp3)"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-005')

@rds.command('check-long-backup-retention')
@common_options
@click.pass_context
def rds_check_long_backup_retention(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find long backup retention on dev/test"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-006')

@rds.command('check-no-performance-insights')
@common_options
@click.pass_context
def rds_check_no_performance_insights(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances without Performance Insights"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-007')

@rds.command('check-public-databases')
@common_options
@click.pass_context
def rds_check_public_databases(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find publicly accessible databases"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-008')

@rds.command('check-unencrypted')
@common_options
@click.pass_context
def rds_check_unencrypted(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find unencrypted RDS storage"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-009')

@rds.command('check-default-username')
@common_options
@click.pass_context
def rds_check_default_username(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find default master usernames"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-010')

@rds.command('check-wide-cidr')
@common_options
@click.pass_context
def rds_check_wide_cidr(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find wide CIDR in RDS security groups"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-011')

@rds.command('check-no-backups')
@common_options
@click.pass_context
def rds_check_no_backups(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find databases with backups disabled"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-012')

@rds.command('check-outdated-engine')
@common_options
@click.pass_context
def rds_check_outdated_engine(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find outdated engine versions"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-013')

@rds.command('check-no-auto-upgrade')
@common_options
@click.pass_context
def rds_check_no_auto_upgrade(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances without auto minor version upgrade"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-014')

@rds.command('check-no-event-subscriptions')
@common_options
@click.pass_context
def rds_check_no_event_subscriptions(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find missing RDS event subscriptions"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-015')

@rds.command('check-no-ssl')
@common_options
@click.pass_context
def rds_check_no_ssl(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find databases without SSL enforcement"""
    execute_engine_command(ctx, 'RDS', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-rds-016')

