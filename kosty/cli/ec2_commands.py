import click
from .utils import common_options, execute_engine_command

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
    execute_engine_command(ctx, 'EC2', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days, cpu_threshold=cpu_threshold)

@ec2.command('cost-audit')
@click.option('--days', default=7, help='Days threshold for stopped/idle instances')
@click.option('--cpu-threshold', default=20, help='CPU utilization threshold')
@common_options
@click.pass_context
def ec2_cost_audit(ctx, days, cpu_threshold, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run EC2 cost optimization audit only"""
    execute_engine_command(ctx, 'EC2', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days, cpu_threshold=cpu_threshold)

@ec2.command('security-audit')
@click.option('--days', default=180, help='Days threshold for AMI age')
@common_options
@click.pass_context
def ec2_security_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run EC2 security audit only"""
    execute_engine_command(ctx, 'EC2', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)

# Individual EC2 checks
@ec2.command('check-oversized-instances')
@click.option('--cpu-threshold', default=20, help='CPU utilization threshold')
@click.option('--days', default=14, help='Days to analyze')
@common_options
@click.pass_context
def ec2_check_oversized(ctx, cpu_threshold, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find oversized EC2 instances"""
    execute_engine_command(ctx, 'EC2', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ec2-003', cpu_threshold=cpu_threshold, days=days)

@ec2.command('check-stopped-instances')
@click.option('--days', default=7, help='Days threshold for stopped instances')
@common_options
@click.pass_context
def ec2_check_stopped(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find stopped EC2 instances"""
    execute_engine_command(ctx, 'EC2', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ec2-001', days=days)

@ec2.command('check-idle-instances')
@click.option('--cpu-threshold', default=5, help='CPU utilization threshold')
@click.option('--days', default=14, help='Days to analyze')
@common_options
@click.pass_context
def ec2_check_idle(ctx, cpu_threshold, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find idle EC2 instances"""
    execute_engine_command(ctx, 'EC2', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ec2-002', cpu_threshold=cpu_threshold, days=days)

@ec2.command('check-previous-generation')
@common_options
@click.pass_context
def ec2_check_previous_gen(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find previous generation instance types"""
    execute_engine_command(ctx, 'EC2', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ec2-004')

@ec2.command('check-ssh-open')
@common_options
@click.pass_context
def ec2_check_ssh(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances with SSH open to internet"""
    execute_engine_command(ctx, 'EC2', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ec2-005')

@ec2.command('check-rdp-open')
@common_options
@click.pass_context
def ec2_check_rdp(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances with RDP open to internet"""
    execute_engine_command(ctx, 'EC2', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ec2-006')

@ec2.command('check-database-ports-open')
@common_options
@click.pass_context
def ec2_check_db_ports(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances with database ports open to internet"""
    execute_engine_command(ctx, 'EC2', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ec2-007')

@ec2.command('check-public-non-web')
@common_options
@click.pass_context
def ec2_check_public_non_web(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find public IPs on non-web instances"""
    execute_engine_command(ctx, 'EC2', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ec2-008')

@ec2.command('check-old-ami')
@click.option('--days', default=180, help='Days threshold for AMI age')
@common_options
@click.pass_context
def ec2_check_old_ami(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances using old AMIs"""
    execute_engine_command(ctx, 'EC2', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ec2-009', days=days)

@ec2.command('check-imdsv1')
@common_options
@click.pass_context
def ec2_check_imdsv1(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances using IMDSv1"""
    execute_engine_command(ctx, 'EC2', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ec2-010')

@ec2.command('check-unencrypted-ebs')
@common_options
@click.pass_context
def ec2_check_unencrypted_ebs(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances with unencrypted EBS volumes"""
    execute_engine_command(ctx, 'EC2', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ec2-011')

@ec2.command('check-no-recent-backup')
@click.option('--days', default=30, help='Days threshold for backup age')
@common_options
@click.pass_context
def ec2_check_no_backup(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find instances with no recent AMI backup"""
    execute_engine_command(ctx, 'EC2', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-ec2-012', days=days)
