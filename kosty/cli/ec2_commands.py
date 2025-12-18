import click
from .utils import common_options, execute_service_command

@click.group()
@click.pass_context
def ec2(ctx):
    """EC2 operations"""
    pass

@ec2.command('audit')
@click.option('--days', default=7, help='Days threshold for stopped/idle instances')
@click.option('--cpu-threshold', default=20, help='CPU utilization threshold')
@common_options
@click.pass_context
def ec2_audit(ctx, days, cpu_threshold, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run complete EC2 audit (cost + security)"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days, cpu_threshold=cpu_threshold)

@ec2.command('cost-audit')
@click.option('--days', default=7, help='Days threshold for stopped/idle instances')
@click.option('--cpu-threshold', default=20, help='CPU utilization threshold')
@common_options
@click.pass_context
def ec2_cost_audit(ctx, days, cpu_threshold, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run EC2 cost optimization audit only"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days, cpu_threshold=cpu_threshold)

@ec2.command('security-audit')
@click.option('--days', default=180, help='Days threshold for AMI age')
@common_options
@click.pass_context
def ec2_security_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run EC2 security audit only"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

# Individual EC2 checks
@ec2.command('check-oversized-instances')
@click.option('--cpu-threshold', default=20, help='CPU utilization threshold')
@click.option('--days', default=14, help='Days to analyze')
@common_options
@click.pass_context
def ec2_check_oversized(ctx, cpu_threshold, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find oversized EC2 instances"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'check_oversized_instances', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, cpu_threshold=cpu_threshold, days=days)

@ec2.command('check-stopped-instances')
@click.option('--days', default=7, help='Days threshold for stopped instances')
@common_options
@click.pass_context
def ec2_check_stopped(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find stopped EC2 instances"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'check_stopped_instances', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@ec2.command('check-idle-instances')
@click.option('--cpu-threshold', default=5, help='CPU utilization threshold')
@click.option('--days', default=7, help='Days to analyze')
@common_options
@click.pass_context
def ec2_check_idle(ctx, cpu_threshold, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find idle EC2 instances"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'check_idle_instances', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, cpu_threshold=cpu_threshold, days=days)

@ec2.command('check-previous-generation')
@common_options
@click.pass_context
def ec2_check_previous_gen(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find previous generation instances (t2/m4/c4)"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'check_previous_generation', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

# Security checks
@ec2.command('check-ssh-open')
@common_options
@click.pass_context
def ec2_check_ssh(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances with SSH open to 0.0.0.0/0"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'check_ssh_open', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@ec2.command('check-rdp-open')
@common_options
@click.pass_context
def ec2_check_rdp(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances with RDP open to 0.0.0.0/0"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'check_rdp_open', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@ec2.command('check-database-ports-open')
@common_options
@click.pass_context
def ec2_check_db_ports(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances with database ports open to 0.0.0.0/0"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'check_database_ports_open', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@ec2.command('check-public-non-web')
@common_options
@click.pass_context
def ec2_check_public_non_web(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find public IP on non-web instances"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'check_public_non_web', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@ec2.command('check-old-ami')
@click.option('--days', default=180, help='Days threshold for AMI age')
@common_options
@click.pass_context
def ec2_check_old_ami(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances using AMI older than X days"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'check_old_ami', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

@ec2.command('check-imdsv1')
@common_options
@click.pass_context
def ec2_check_imdsv1(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances using IMDSv1"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'check_imdsv1', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@ec2.command('check-unencrypted-ebs')
@common_options
@click.pass_context
def ec2_check_unencrypted_ebs(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances with unencrypted EBS volumes"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'check_unencrypted_ebs', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)

@ec2.command('check-no-recent-backup')
@click.option('--days', default=30, help='Days threshold for recent AMI backup')
@common_options
@click.pass_context
def ec2_check_no_backup(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances with no recent AMI backup"""
    from ..services.ec2_audit import EC2AuditService
    execute_service_command(ctx, EC2AuditService, 'check_no_recent_backup', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)