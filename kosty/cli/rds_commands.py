import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def rds(ctx):
    """RDS operations"""
    pass

@rds.command('audit')
@click.option('--days', default=7, help='Days threshold for idle/oversized analysis')
@click.option('--cpu-threshold', default=20, help='CPU utilization threshold')
@common_options
@click.pass_context
def rds_audit(ctx, days, cpu_threshold, organization, region, max_workers, regions, output):
    """Run complete RDS audit (cost + security)"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'audit', output, organization, region, max_workers, regions, days=days, cpu_threshold=cpu_threshold)

@rds.command('cost-audit')
@click.option('--days', default=7, help='Days threshold for idle/oversized analysis')
@click.option('--cpu-threshold', default=20, help='CPU utilization threshold')
@common_options
@click.pass_context
def rds_cost_audit(ctx, days, cpu_threshold, organization, region, max_workers, regions, output):
    """Run RDS cost optimization audit only"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'cost_audit', output, organization, region, max_workers, regions, days=days, cpu_threshold=cpu_threshold)

@rds.command('security-audit')
@common_options
@click.pass_context
def rds_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run RDS security audit only"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'security_audit', output, organization, region, max_workers, regions)

@rds.command('check-oversized-instances')
@click.option('--cpu-threshold', default=20, help='CPU utilization threshold')
@click.option('--days', default=7, help='Days to analyze')
@common_options
@click.pass_context
def rds_check_oversized(ctx, cpu_threshold, days, organization, region, max_workers, regions, output):
    """Find oversized RDS instances"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'check_oversized_instances', output, organization, region, max_workers, regions, cpu_threshold=cpu_threshold, days=days)

# Cost optimization checks
@rds.command('check-idle-instances')
@click.option('--days', default=7, help='Days threshold for idle analysis')
@click.option('--cpu-threshold', default=5, help='CPU utilization threshold')
@common_options
@click.pass_context
def rds_check_idle(ctx, days, cpu_threshold, organization, region, max_workers, regions, output):
    """Find idle RDS instances (<5% CPU for 7 days)"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'check_idle_instances', output, organization, region, max_workers, regions, days=days, cpu_threshold=cpu_threshold)

@rds.command('check-unused-read-replicas')
@click.option('--days', default=7, help='Days threshold for read analysis')
@click.option('--read-threshold', default=100, help='Read operations per day threshold')
@common_options
@click.pass_context
def rds_check_unused_replicas(ctx, days, read_threshold, organization, region, max_workers, regions, output):
    """Find unused read replicas (<100 reads/day)"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'check_unused_read_replicas', output, organization, region, max_workers, regions, days=days, read_threshold=read_threshold)

@rds.command('check-multi-az-non-prod')
@common_options
@click.pass_context
def rds_check_multi_az(ctx, organization, region, max_workers, regions, output):
    """Find Multi-AZ for non-production"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'check_multi_az_non_prod', output, organization, region, max_workers, regions)

@rds.command('check-long-backup-retention')
@click.option('--retention-threshold', default=7, help='Backup retention days threshold')
@common_options
@click.pass_context
def rds_check_backup_retention(ctx, retention_threshold, organization, region, max_workers, regions, output):
    """Find backup retention >7 days for dev/test"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'check_long_backup_retention', output, organization, region, max_workers, regions, retention_threshold=retention_threshold)

@rds.command('check-gp2-storage')
@common_options
@click.pass_context
def rds_check_gp2(ctx, organization, region, max_workers, regions, output):
    """Find gp2 storage (should be gp3)"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'check_gp2_storage', output, organization, region, max_workers, regions)

# Security checks
@rds.command('check-public-databases')
@common_options
@click.pass_context
def rds_check_public(ctx, organization, region, max_workers, regions, output):
    """Find publicly accessible RDS instances"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'check_publicly_accessible', output, organization, region, max_workers, regions)

@rds.command('check-unencrypted-storage')
@common_options
@click.pass_context
def rds_check_unencrypted(ctx, organization, region, max_workers, regions, output):
    """Find storage not encrypted"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'check_unencrypted_storage', output, organization, region, max_workers, regions)

@rds.command('check-default-username')
@common_options
@click.pass_context
def rds_check_default_username(ctx, organization, region, max_workers, regions, output):
    """Find master username is default (admin/root/postgres)"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'check_default_username', output, organization, region, max_workers, regions)

@rds.command('check-wide-cidr-sg')
@common_options
@click.pass_context
def rds_check_wide_cidr(ctx, organization, region, max_workers, regions, output):
    """Find security group allows wide CIDR (>=/16)"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'check_wide_cidr_sg', output, organization, region, max_workers, regions)

@rds.command('check-disabled-backups')
@common_options
@click.pass_context
def rds_check_disabled_backups(ctx, organization, region, max_workers, regions, output):
    """Find automated backups disabled (retention=0)"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'check_disabled_backups', output, organization, region, max_workers, regions)

@rds.command('check-outdated-engine')
@click.option('--months-threshold', default=12, help='Engine version age threshold in months')
@common_options
@click.pass_context
def rds_check_outdated_engine(ctx, months_threshold, organization, region, max_workers, regions, output):
    """Find engine version outdated (>12 months)"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'check_outdated_engine', output, organization, region, max_workers, regions, months_threshold=months_threshold)

@rds.command('check-no-ssl-enforcement')
@common_options
@click.pass_context
def rds_check_no_ssl(ctx, organization, region, max_workers, regions, output):
    """Find no SSL/TLS enforcement"""
    from ..services.rds_audit import RDSAuditService
    execute_service_command(ctx, RDSAuditService, 'check_no_ssl_enforcement', output, organization, region, max_workers, regions)