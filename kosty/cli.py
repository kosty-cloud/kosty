#!/usr/bin/env python3
import click
import asyncio

# Services are imported dynamically when needed to avoid import errors
from .core.executor import ServiceExecutor

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

@click.group(invoke_without_command=True)
@click.option('--organization', is_flag=True, help='Run across organization accounts')
@click.option('--region', default='us-east-1', help='AWS region')
@click.option('--max-workers', default=5, help='Maximum concurrent workers')
@click.option('--all', 'run_all', is_flag=True, help='Run comprehensive scan of all services')
@click.option('--output', default='console', type=click.Choice(['console', 'json', 'csv', 'all']), help='Output format')
@click.pass_context
def cli(ctx, run_all, organization, region, max_workers, output):
    """Kosty - AWS Cost Optimization Tool"""
    ctx.ensure_object(dict)
    ctx.obj['organization'] = organization
    ctx.obj['region'] = region
    ctx.obj['max_workers'] = max_workers
    
    if run_all:
        from .core.scanner import ComprehensiveScanner
        import asyncio
        
        scanner = ComprehensiveScanner(organization, region, max_workers)
        reporter = asyncio.run(scanner.run_comprehensive_scan())
        
        # Generate reports based on output format
        if output in ['console', 'all']:
            print(reporter.generate_summary_report())
        
        if output in ['json', 'all']:
            json_file = reporter.save_json_report()
            print(f"\\n📄 Detailed JSON report saved: {json_file}")
        
        if output in ['csv', 'all']:
            csv_file = reporter.save_csv_report()
            print(f"📊 CSV report saved: {csv_file}")
        
        if output == 'all':
            print(f"\\n🎉 All reports generated successfully!")
            total_issues = sum(sum(cmd['count'] for cmd in svc.values()) for acc in reporter.results.values() for svc in acc.values())
            print(f"📊 Total issues found: {total_issues}")
        
        return
    
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())

# EC2 Commands
@cli.group()
@click.pass_context
def ec2(ctx):
    """EC2 operations"""
    pass

@ec2.command('audit')
@click.option('--days', default=7, help='Days threshold for stopped/idle instances')
@click.option('--cpu-threshold', default=20, help='CPU utilization threshold')
@common_options
@click.pass_context
def ec2_audit(ctx, days, cpu_threshold, organization, region, max_workers, regions, output):
    """Run complete EC2 audit (cost + security)"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output, days=days, cpu_threshold=cpu_threshold))

@ec2.command('cost-audit')
@click.option('--days', default=7, help='Days threshold for stopped/idle instances')
@click.option('--cpu-threshold', default=20, help='CPU utilization threshold')
@common_options
@click.pass_context
def ec2_cost_audit(ctx, days, cpu_threshold, organization, region, max_workers, regions, output):
    """Run EC2 cost optimization audit only"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output, days=days, cpu_threshold=cpu_threshold))

@ec2.command('security-audit')
@click.option('--days', default=180, help='Days threshold for AMI age')
@common_options
@click.pass_context
def ec2_security_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run EC2 security audit only"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output, days=days))

# Individual EC2 checks
@ec2.command('check-oversized-instances')
@click.option('--cpu-threshold', default=20, help='CPU utilization threshold')
@click.option('--days', default=14, help='Days to analyze')
@common_options
@click.pass_context
def ec2_check_oversized(ctx, cpu_threshold, days, organization, region, max_workers, regions, output):
    """Find oversized EC2 instances"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_oversized_instances', output, cpu_threshold=cpu_threshold, days=days))

@ec2.command('check-stopped-instances')
@click.option('--days', default=7, help='Days threshold for stopped instances')
@common_options
@click.pass_context
def ec2_check_stopped(ctx, days, organization, region, max_workers, regions, output):
    """Find stopped EC2 instances"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_stopped_instances', output, days=days))

@ec2.command('check-idle-instances')
@click.option('--cpu-threshold', default=5, help='CPU utilization threshold')
@click.option('--days', default=7, help='Days to analyze')
@common_options
@click.pass_context
def ec2_check_idle(ctx, cpu_threshold, days, organization, region, max_workers, regions, output):
    """Find idle EC2 instances"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_idle_instances', output, cpu_threshold=cpu_threshold, days=days))

@ec2.command('check-previous-generation')
@common_options
@click.pass_context
def ec2_check_previous_gen(ctx, organization, region, max_workers, regions, output):
    """Find previous generation instances (t2/m4/c4)"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_previous_generation', output))

# Security checks
@ec2.command('check-ssh-open')
@common_options
@click.pass_context
def ec2_check_ssh(ctx, organization, region, max_workers, regions, output):
    """Find instances with SSH open to 0.0.0.0/0"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_ssh_open', output))

@ec2.command('check-rdp-open')
@common_options
@click.pass_context
def ec2_check_rdp(ctx, organization, region, max_workers, regions, output):
    """Find instances with RDP open to 0.0.0.0/0"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_rdp_open', output))

@ec2.command('check-database-ports-open')
@common_options
@click.pass_context
def ec2_check_db_ports(ctx, organization, region, max_workers, regions, output):
    """Find instances with database ports open to 0.0.0.0/0"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_database_ports_open', output))

@ec2.command('check-public-non-web')
@common_options
@click.pass_context
def ec2_check_public_non_web(ctx, organization, region, max_workers, regions, output):
    """Find public IP on non-web instances"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_public_non_web', output))

@ec2.command('check-old-ami')
@click.option('--days', default=180, help='Days threshold for AMI age')
@common_options
@click.pass_context
def ec2_check_old_ami(ctx, days, organization, region, max_workers, regions, output):
    """Find instances using AMI older than X days"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_old_ami', output, days=days))

@ec2.command('check-imdsv1')
@common_options
@click.pass_context
def ec2_check_imdsv1(ctx, organization, region, max_workers, regions, output):
    """Find instances using IMDSv1"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_imdsv1', output))

@ec2.command('check-unencrypted-ebs')
@common_options
@click.pass_context
def ec2_check_unencrypted_ebs(ctx, organization, region, max_workers, regions, output):
    """Find instances with unencrypted EBS volumes"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_unencrypted_ebs', output))

@ec2.command('check-no-recent-backup')
@click.option('--days', default=30, help='Days threshold for recent AMI backup')
@common_options
@click.pass_context
def ec2_check_no_backup(ctx, days, organization, region, max_workers, regions, output):
    """Find instances with no recent AMI backup"""
    from .services.ec2_audit import EC2AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EC2AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_no_recent_backup', output, days=days))

# S3 Commands
@cli.group()
@click.pass_context
def s3(ctx):
    """S3 operations"""
    pass

@s3.command('audit')
@click.option('--days', default=90, help='Days threshold for lifecycle candidates')
@common_options
@click.pass_context
def s3_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run complete S3 audit (cost + security)"""
    from .services.s3_audit import S3AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = S3AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output, days=days))

@s3.command('cost-audit')
@click.option('--days', default=90, help='Days threshold for lifecycle candidates')
@common_options
@click.pass_context
def s3_cost_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run S3 cost optimization audit only"""
    from .services.s3_audit import S3AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = S3AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output, days=days))

@s3.command('security-audit')
@common_options
@click.pass_context
def s3_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run S3 security audit only"""
    from .services.s3_audit import S3AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = S3AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output))

@s3.command('check-empty-buckets')
@common_options
@click.pass_context
def s3_check_empty(ctx, organization, region, max_workers, regions, output):
    """Find empty S3 buckets"""
    from .services.s3_audit import S3AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = S3AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_empty_buckets', output))

@s3.command('check-incomplete-uploads')
@click.option('--days', default=7, help='Days threshold for incomplete uploads')
@common_options
@click.pass_context
def s3_check_incomplete_uploads(ctx, days, organization, region, max_workers, regions, output):
    """Find incomplete multipart uploads"""
    from .services.s3_audit import S3AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = S3AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_incomplete_uploads', output, days=days))

@s3.command('check-lifecycle-policy')
@click.option('--days', default=90, help='Days threshold for lifecycle candidates')
@common_options
@click.pass_context
def s3_check_lifecycle_policy(ctx, days, organization, region, max_workers, regions, output):
    """Find buckets needing lifecycle policies"""
    from .services.s3_audit import S3AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = S3AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_lifecycle_policy', output, days=days))

@s3.command('check-public-read-access')
@common_options
@click.pass_context
def s3_check_public_read(ctx, organization, region, max_workers, regions, output):
    """Find buckets with public read access"""
    from .services.s3_audit import S3AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = S3AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_public_read_access', output))

@s3.command('check-public-write-access')
@common_options
@click.pass_context
def s3_check_public_write(ctx, organization, region, max_workers, regions, output):
    """Find buckets with public write access"""
    from .services.s3_audit import S3AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = S3AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_public_write_access', output))

@s3.command('check-encryption-at-rest')
@common_options
@click.pass_context
def s3_check_encryption(ctx, organization, region, max_workers, regions, output):
    """Find buckets without encryption"""
    from .services.s3_audit import S3AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = S3AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_encryption_at_rest', output))

@s3.command('check-versioning-disabled')
@common_options
@click.pass_context
def s3_check_versioning(ctx, organization, region, max_workers, regions, output):
    """Find buckets without versioning"""
    from .services.s3_audit import S3AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = S3AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_versioning_disabled', output))

@s3.command('check-access-logging')
@common_options
@click.pass_context
def s3_check_logging(ctx, organization, region, max_workers, regions, output):
    """Find buckets without access logging"""
    from .services.s3_audit import S3AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = S3AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_access_logging', output))

@s3.command('check-bucket-policy-wildcards')
@common_options
@click.pass_context
def s3_check_wildcards(ctx, organization, region, max_workers, regions, output):
    """Find buckets with wildcard policies"""
    from .services.s3_audit import S3AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = S3AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_bucket_policy_wildcards', output))

@s3.command('check-mfa-delete')
@common_options
@click.pass_context
def s3_check_mfa_delete(ctx, organization, region, max_workers, regions, output):
    """Find buckets without MFA delete"""
    from .services.s3_audit import S3AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = S3AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_mfa_delete', output))

# RDS Commands
@cli.group()
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
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output, days=days, cpu_threshold=cpu_threshold))

@rds.command('cost-audit')
@click.option('--days', default=7, help='Days threshold for idle/oversized analysis')
@click.option('--cpu-threshold', default=20, help='CPU utilization threshold')
@common_options
@click.pass_context
def rds_cost_audit(ctx, days, cpu_threshold, organization, region, max_workers, regions, output):
    """Run RDS cost optimization audit only"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output, days=days, cpu_threshold=cpu_threshold))

@rds.command('security-audit')
@common_options
@click.pass_context
def rds_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run RDS security audit only"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output))

@rds.command('check-oversized-instances')
@click.option('--cpu-threshold', default=20, help='CPU utilization threshold')
@click.option('--days', default=7, help='Days to analyze')
@common_options
@click.pass_context
def rds_check_oversized(ctx, cpu_threshold, days, organization, region, max_workers, regions, output):
    """Find oversized RDS instances"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_oversized_instances', output, cpu_threshold=cpu_threshold, days=days))

# Cost optimization checks
@rds.command('check-idle-instances')
@click.option('--days', default=7, help='Days threshold for idle analysis')
@click.option('--cpu-threshold', default=5, help='CPU utilization threshold')
@common_options
@click.pass_context
def rds_check_idle(ctx, days, cpu_threshold, organization, region, max_workers, regions, output):
    """Find idle RDS instances (<5% CPU for 7 days)"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_idle_instances', output, days=days, cpu_threshold=cpu_threshold))

@rds.command('check-unused-read-replicas')
@click.option('--days', default=7, help='Days threshold for read analysis')
@click.option('--read-threshold', default=100, help='Read operations per day threshold')
@common_options
@click.pass_context
def rds_check_unused_replicas(ctx, days, read_threshold, organization, region, max_workers, regions, output):
    """Find unused read replicas (<100 reads/day)"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_unused_read_replicas', output, days=days, read_threshold=read_threshold))

@rds.command('check-multi-az-non-prod')
@common_options
@click.pass_context
def rds_check_multi_az(ctx, organization, region, max_workers, regions, output):
    """Find Multi-AZ for non-production"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_multi_az_non_prod', output))

@rds.command('check-long-backup-retention')
@click.option('--retention-threshold', default=7, help='Backup retention days threshold')
@common_options
@click.pass_context
def rds_check_backup_retention(ctx, retention_threshold, organization, region, max_workers, regions, output):
    """Find backup retention >7 days for dev/test"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_long_backup_retention', output, retention_threshold=retention_threshold))

@rds.command('check-gp2-storage')
@common_options
@click.pass_context
def rds_check_gp2(ctx, organization, region, max_workers, regions, output):
    """Find gp2 storage (should be gp3)"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_gp2_storage', output))

# Security checks
@rds.command('check-public-databases')
@common_options
@click.pass_context
def rds_check_public(ctx, organization, region, max_workers, regions, output):
    """Find publicly accessible RDS instances"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_publicly_accessible', output))

@rds.command('check-unencrypted-storage')
@common_options
@click.pass_context
def rds_check_unencrypted(ctx, organization, region, max_workers, regions, output):
    """Find storage not encrypted"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_unencrypted_storage', output))

@rds.command('check-default-username')
@common_options
@click.pass_context
def rds_check_default_username(ctx, organization, region, max_workers, regions, output):
    """Find master username is default (admin/root/postgres)"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_default_username', output))

@rds.command('check-wide-cidr-sg')
@common_options
@click.pass_context
def rds_check_wide_cidr(ctx, organization, region, max_workers, regions, output):
    """Find security group allows wide CIDR (>=/16)"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_wide_cidr_sg', output))

@rds.command('check-disabled-backups')
@common_options
@click.pass_context
def rds_check_disabled_backups(ctx, organization, region, max_workers, regions, output):
    """Find automated backups disabled (retention=0)"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_disabled_backups', output))

@rds.command('check-outdated-engine')
@click.option('--months-threshold', default=12, help='Engine version age threshold in months')
@common_options
@click.pass_context
def rds_check_outdated_engine(ctx, months_threshold, organization, region, max_workers, regions, output):
    """Find engine version outdated (>12 months)"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_outdated_engine', output, months_threshold=months_threshold))

@rds.command('check-no-ssl-enforcement')
@common_options
@click.pass_context
def rds_check_no_ssl(ctx, organization, region, max_workers, regions, output):
    """Find no SSL/TLS enforcement"""
    from .services.rds_audit import RDSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = RDSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_no_ssl_enforcement', output))

# Lambda Commands
@cli.group(name='lambda')
@click.pass_context
def lambda_func(ctx):
    """Lambda operations"""
    pass

@lambda_func.command('audit')
@click.option('--days', default=30, help='Days threshold for unused functions')
@common_options
@click.pass_context
def lambda_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run complete Lambda audit"""
    from .services.lambda_audit import LambdaAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LambdaAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output, days=days))

@lambda_func.command('cost-audit')
@click.option('--days', default=30, help='Days threshold for unused functions')
@common_options
@click.pass_context
def lambda_cost_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run Lambda cost optimization audit only"""
    from .services.lambda_audit import LambdaAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LambdaAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output, days=days))

@lambda_func.command('check-unused-functions')
@click.option('--days', default=30, help='Days threshold for unused functions')
@common_options
@click.pass_context
def lambda_check_unused(ctx, days, organization, region, max_workers, regions, output):
    """Find unused Lambda functions"""
    from .services.lambda_audit import LambdaAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LambdaAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_unused_functions', output, days=days))

@lambda_func.command('security-audit')
@common_options
@click.pass_context
def lambda_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run Lambda security audit only"""
    from .services.lambda_audit import LambdaAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LambdaAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output))

@lambda_func.command('check-over-provisioned-memory')
@common_options
@click.pass_context
def lambda_check_memory(ctx, organization, region, max_workers, regions, output):
    """Find over-provisioned Lambda functions"""
    from .services.lambda_audit import LambdaAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LambdaAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_over_provisioned_memory', output))

@lambda_func.command('check-long-timeout-functions')
@common_options
@click.pass_context
def lambda_check_timeout(ctx, organization, region, max_workers, regions, output):
    """Find Lambda functions with long timeouts"""
    from .services.lambda_audit import LambdaAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LambdaAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_long_timeout_functions', output))

@lambda_func.command('check-public-functions')
@common_options
@click.pass_context
def lambda_check_public(ctx, organization, region, max_workers, regions, output):
    """Find publicly accessible Lambda functions"""
    from .services.lambda_audit import LambdaAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LambdaAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_public_functions', output))

# EBS Commands
@cli.group()
@click.pass_context
def ebs(ctx):
    """EBS volume operations"""
    pass

@ebs.command('audit')
@click.option('--days', default=7, help='Days threshold for I/O analysis and snapshots')
@common_options
@click.pass_context
def ebs_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run complete EBS audit (cost + security)"""
    from .services.ebs_audit import EBSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EBSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output, days=days))

@ebs.command('cost-audit')
@click.option('--days', default=7, help='Days threshold for I/O analysis')
@common_options
@click.pass_context
def ebs_cost_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run EBS cost optimization audit only"""
    from .services.ebs_audit import EBSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EBSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output, days=days))

@ebs.command('security-audit')
@common_options
@click.pass_context
def ebs_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run EBS security audit only"""
    from .services.ebs_audit import EBSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EBSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output))

# Cost optimization checks
@ebs.command('check-orphan-volumes')
@common_options
@click.pass_context
def ebs_check_orphan(ctx, organization, region, max_workers, regions, output):
    """Find orphaned EBS volumes"""
    from .services.ebs_audit import EBSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EBSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_orphan_volumes', output))

@ebs.command('check-low-io-volumes')
@click.option('--iops-threshold', default=10, help='IOPS per GB threshold')
@click.option('--days', default=7, help='Days to analyze I/O')
@common_options
@click.pass_context
def ebs_check_low_io(ctx, iops_threshold, days, organization, region, max_workers, regions, output):
    """Find volumes with low I/O"""
    from .services.ebs_audit import EBSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EBSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_low_io_volumes', output, iops_threshold=iops_threshold, days=days))

@ebs.command('check-old-snapshots')
@click.option('--days', default=90, help='Days threshold for old snapshots')
@common_options
@click.pass_context
def ebs_check_old_snapshots(ctx, days, organization, region, max_workers, regions, output):
    """Find old EBS snapshots"""
    from .services.ebs_audit import EBSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EBSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_old_snapshots', output, days=days))

@ebs.command('check-gp2-volumes')
@common_options
@click.pass_context
def ebs_check_gp2(ctx, organization, region, max_workers, regions, output):
    """Find gp2 volumes (should be gp3)"""
    from .services.ebs_audit import EBSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EBSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_gp2_volumes', output))

# Security checks
@ebs.command('check-unencrypted-orphan')
@common_options
@click.pass_context
def ebs_check_unencrypted_orphan(ctx, organization, region, max_workers, regions, output):
    """Find unencrypted orphaned volumes"""
    from .services.ebs_audit import EBSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EBSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_unencrypted_orphan', output))

@ebs.command('check-unencrypted-in-use')
@common_options
@click.pass_context
def ebs_check_unencrypted_in_use(ctx, organization, region, max_workers, regions, output):
    """Find unencrypted volumes in use"""
    from .services.ebs_audit import EBSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EBSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_unencrypted_in_use', output))

@ebs.command('check-public-snapshots')
@common_options
@click.pass_context
def ebs_check_public_snapshots(ctx, organization, region, max_workers, regions, output):
    """Find public snapshots"""
    from .services.ebs_audit import EBSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EBSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_public_snapshots', output))

@ebs.command('check-no-recent-snapshot')
@click.option('--days', default=7, help='Days threshold for recent snapshots')
@common_options
@click.pass_context
def ebs_check_no_recent_snapshot(ctx, days, organization, region, max_workers, regions, output):
    """Find volumes with no recent snapshots"""
    from .services.ebs_audit import EBSAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EBSAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_no_recent_snapshot', output, days=days))

# IAM Commands
@cli.group()
@click.pass_context
def iam(ctx):
    """IAM operations"""
    pass

@iam.command('audit')
@click.option('--days', default=90, help='Days threshold for unused roles, inactive users and old keys')
@common_options
@click.pass_context
def iam_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run complete IAM audit (cost + security)"""
    from .services.iam_audit import IAMAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = IAMAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output, days=days))

@iam.command('security-audit')
@click.option('--days', default=90, help='Days threshold for unused roles, inactive users and old keys')
@common_options
@click.pass_context
def iam_security_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run IAM security audit only"""
    from .services.iam_audit import IAMAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = IAMAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output, days=days))

@iam.command('check-root-access-keys')
@common_options
@click.pass_context
def iam_check_root_keys(ctx, organization, region, max_workers, regions, output):
    """Find root account access keys"""
    from .services.iam_audit import IAMAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = IAMAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_root_access_keys', output))

@iam.command('cost-audit')
@click.option('--days', default=90, help='Days threshold for unused roles')
@common_options
@click.pass_context
def iam_cost_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run IAM cost optimization audit only"""
    from .services.iam_audit import IAMAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = IAMAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output, days=days))

@iam.command('check-unused-roles')
@click.option('--days', default=90, help='Days threshold for unused roles')
@common_options
@click.pass_context
def iam_check_unused_roles(ctx, days, organization, region, max_workers, regions, output):
    """Find unused IAM roles"""
    from .services.iam_audit import IAMAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = IAMAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_unused_roles', output, days=days))

@iam.command('check-inactive-users')
@click.option('--days', default=90, help='Days threshold for inactive users')
@common_options
@click.pass_context
def iam_check_inactive_users(ctx, days, organization, region, max_workers, regions, output):
    """Find inactive IAM users"""
    from .services.iam_audit import IAMAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = IAMAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_inactive_users', output, days=days))

@iam.command('check-old-access-keys')
@click.option('--days', default=90, help='Days threshold for old access keys')
@common_options
@click.pass_context
def iam_check_old_keys(ctx, days, organization, region, max_workers, regions, output):
    """Find old IAM access keys"""
    from .services.iam_audit import IAMAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = IAMAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_old_access_keys', output, days=days))

@iam.command('check-wildcard-policies')
@common_options
@click.pass_context
def iam_check_wildcard_policies(ctx, organization, region, max_workers, regions, output):
    """Find IAM policies with wildcard permissions"""
    from .services.iam_audit import IAMAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = IAMAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_wildcard_policies', output))

@iam.command('check-admin-no-mfa')
@common_options
@click.pass_context
def iam_check_admin_no_mfa(ctx, organization, region, max_workers, regions, output):
    """Find admin users without MFA"""
    from .services.iam_audit import IAMAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = IAMAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_admin_no_mfa', output))

@iam.command('check-weak-password-policy')
@common_options
@click.pass_context
def iam_check_weak_password(ctx, organization, region, max_workers, regions, output):
    """Find weak password policy"""
    from .services.iam_audit import IAMAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = IAMAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_weak_password_policy', output))

@iam.command('check-no-password-rotation')
@common_options
@click.pass_context
def iam_check_no_rotation(ctx, organization, region, max_workers, regions, output):
    """Find users with no password rotation"""
    from .services.iam_audit import IAMAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = IAMAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_no_password_rotation', output))

@iam.command('check-cross-account-no-external-id')
@common_options
@click.pass_context
def iam_check_cross_account(ctx, organization, region, max_workers, regions, output):
    """Find cross-account roles without external ID"""
    from .services.iam_audit import IAMAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = IAMAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_cross_account_no_external_id', output))

# EIP Commands
@cli.group()
@click.pass_context
def eip(ctx):
    """Elastic IP operations"""
    pass

@eip.command('audit')
@common_options
@click.pass_context
def eip_audit(ctx, organization, region, max_workers, regions, output):
    """Run complete EIP audit"""
    from .services.eip_audit import EIPAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EIPAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output))

@eip.command('cost-audit')
@common_options
@click.pass_context
def eip_cost_audit(ctx, organization, region, max_workers, regions, output):
    """Run EIP cost optimization audit only"""
    from .services.eip_audit import EIPAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EIPAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output))

@eip.command('security-audit')
@common_options
@click.pass_context
def eip_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run EIP security audit only"""
    from .services.eip_audit import EIPAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EIPAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output))

@eip.command('check-unattached-eips')
@common_options
@click.pass_context
def eip_check_unattached(ctx, organization, region, max_workers, regions, output):
    """Find unattached Elastic IPs"""
    from .services.eip_audit import EIPAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EIPAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_unattached_eips', output))

@eip.command('check-eips-on-stopped-instances')
@common_options
@click.pass_context
def eip_check_stopped_instances(ctx, organization, region, max_workers, regions, output):
    """Find EIPs attached to stopped instances"""
    from .services.eip_audit import EIPAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EIPAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_eips_on_stopped_instances', output))

@eip.command('check-dangerous-sg-rules')
@common_options
@click.pass_context
def eip_check_dangerous_sg(ctx, organization, region, max_workers, regions, output):
    """Find EIPs with dangerous security group rules"""
    from .services.eip_audit import EIPAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = EIPAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_eips_with_dangerous_sg_rules', output))

# Load Balancer Commands
@cli.group()
@click.pass_context
def lb(ctx):
    """Load Balancer operations"""
    pass

@lb.command('audit')
@common_options
@click.pass_context
def lb_audit(ctx, organization, region, max_workers, regions, output):
    """Run complete Load Balancer audit"""
    from .services.lb_audit import LBAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LBAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output))

@lb.command('cost-audit')
@common_options
@click.pass_context
def lb_cost_audit(ctx, organization, region, max_workers, regions, output):
    """Run Load Balancer cost optimization audit only"""
    from .services.lb_audit import LBAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LBAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output))

@lb.command('security-audit')
@common_options
@click.pass_context
def lb_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run Load Balancer security audit only"""
    from .services.lb_audit import LBAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LBAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output))

@lb.command('check-no-healthy-targets')
@common_options
@click.pass_context
def lb_check_no_targets(ctx, organization, region, max_workers, regions, output):
    """Find load balancers with no healthy targets"""
    from .services.lb_audit import LBAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LBAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_lbs_with_no_healthy_targets', output))

@lb.command('check-underutilized-lbs')
@common_options
@click.pass_context
def lb_check_underutilized(ctx, organization, region, max_workers, regions, output):
    """Find underutilized load balancers"""
    from .services.lb_audit import LBAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LBAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_underutilized_lbs', output))

@lb.command('check-classic-lbs')
@common_options
@click.pass_context
def lb_check_classic(ctx, organization, region, max_workers, regions, output):
    """Find Classic Load Balancers (should be ALB/NLB)"""
    from .services.lb_audit import LBAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LBAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_classic_lbs', output))

@lb.command('check-http-without-https-redirect')
@common_options
@click.pass_context
def lb_check_http_redirect(ctx, organization, region, max_workers, regions, output):
    """Find HTTP listeners without HTTPS redirect"""
    from .services.lb_audit import LBAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LBAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_http_without_https_redirect', output))

@lb.command('check-deprecated-tls-versions')
@common_options
@click.pass_context
def lb_check_tls(ctx, organization, region, max_workers, regions, output):
    """Find load balancers with deprecated TLS versions"""
    from .services.lb_audit import LBAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LBAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_deprecated_tls_versions', output))

@lb.command('check-lbs-without-access-logs')
@common_options
@click.pass_context
def lb_check_access_logs(ctx, organization, region, max_workers, regions, output):
    """Find load balancers without access logs"""
    from .services.lb_audit import LBAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = LBAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_lbs_without_access_logs', output))

# NAT Gateway Commands
@cli.group()
@click.pass_context
def nat(ctx):
    """NAT Gateway operations"""
    pass

@nat.command('audit')
@click.option('--days', default=7, help='Days threshold for data transfer analysis')
@common_options
@click.pass_context
def nat_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run complete NAT Gateway audit"""
    from .services.nat_audit import NATAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = NATAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output, days=days))

@nat.command('cost-audit')
@click.option('--days', default=7, help='Days threshold for data transfer analysis')
@common_options
@click.pass_context
def nat_cost_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run NAT Gateway cost optimization audit only"""
    from .services.nat_audit import NATAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = NATAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output, days=days))

@nat.command('security-audit')
@common_options
@click.pass_context
def nat_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run NAT Gateway security audit only"""
    from .services.nat_audit import NATAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = NATAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output))

@nat.command('check-unused-gateways')
@click.option('--days', default=7, help='Days threshold for usage analysis')
@common_options
@click.pass_context
def nat_check_unused(ctx, days, organization, region, max_workers, regions, output):
    """Find unused NAT Gateways"""
    from .services.nat_audit import NATAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = NATAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_unused_nat_gateways', output, days=days))

@nat.command('check-redundant-gateways')
@common_options
@click.pass_context
def nat_check_redundant(ctx, organization, region, max_workers, regions, output):
    """Find redundant NAT Gateways"""
    from .services.nat_audit import NATAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = NATAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_redundant_nat_gateways', output))

# Security Group Commands
@cli.group()
@click.pass_context
def sg(ctx):
    """Security Group operations"""
    pass

@sg.command('audit')
@common_options
@click.pass_context
def sg_audit(ctx, organization, region, max_workers, regions, output):
    """Run complete Security Group audit"""
    from .services.sg_audit import SGAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = SGAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output))

@sg.command('cost-audit')
@common_options
@click.pass_context
def sg_cost_audit(ctx, organization, region, max_workers, regions, output):
    """Run Security Group cost optimization audit only"""
    from .services.sg_audit import SGAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = SGAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output))

@sg.command('security-audit')
@common_options
@click.pass_context
def sg_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run Security Group security audit only"""
    from .services.sg_audit import SGAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = SGAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output))

@sg.command('check-unused-groups')
@common_options
@click.pass_context
def sg_check_unused(ctx, organization, region, max_workers, regions, output):
    """Find unused security groups"""
    from .services.sg_audit import SGAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = SGAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_unused_groups', output))

@sg.command('check-ssh-rdp-open')
@common_options
@click.pass_context
def sg_check_ssh_rdp(ctx, organization, region, max_workers, regions, output):
    """Find security groups with SSH/RDP open to 0.0.0.0/0"""
    from .services.sg_audit import SGAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = SGAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_ssh_rdp_open', output))

@sg.command('check-database-ports-open')
@common_options
@click.pass_context
def sg_check_db_ports(ctx, organization, region, max_workers, regions, output):
    """Find security groups with database ports open to 0.0.0.0/0"""
    from .services.sg_audit import SGAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = SGAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_database_ports_open', output))

@sg.command('check-all-ports-open')
@common_options
@click.pass_context
def sg_check_all_ports(ctx, organization, region, max_workers, regions, output):
    """Find security groups with all ports open to 0.0.0.0/0"""
    from .services.sg_audit import SGAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = SGAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_all_ports_open', output))

@sg.command('check-complex-security-groups')
@click.option('--rule-threshold', default=50, help='Rule count threshold for complex security groups')
@common_options
@click.pass_context
def sg_check_complex(ctx, rule_threshold, organization, region, max_workers, regions, output):
    """Find security groups with >rule_threshold rules"""
    from .services.sg_audit import SGAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = SGAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_complex_security_groups', output, rule_threshold=rule_threshold))

# CloudWatch Commands
@cli.group()
@click.pass_context
def cloudwatch(ctx):
    """CloudWatch operations"""
    pass

@cloudwatch.command('audit')
@click.option('--days', default=30, help='Days threshold for unused resources')
@common_options
@click.pass_context
def cloudwatch_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run complete CloudWatch audit"""
    from .services.cloudwatch_audit import CloudWatchAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = CloudWatchAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output, days=days))

@cloudwatch.command('cost-audit')
@click.option('--days', default=30, help='Days threshold for unused resources')
@common_options
@click.pass_context
def cloudwatch_cost_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run CloudWatch cost optimization audit only"""
    from .services.cloudwatch_audit import CloudWatchAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = CloudWatchAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output, days=days))

@cloudwatch.command('security-audit')
@common_options
@click.pass_context
def cloudwatch_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run CloudWatch security audit only"""
    from .services.cloudwatch_audit import CloudWatchAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = CloudWatchAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output))

@cloudwatch.command('check-unused-alarms')
@click.option('--days', default=30, help='Days threshold for alarm activity')
@common_options
@click.pass_context
def cloudwatch_check_alarms(ctx, days, organization, region, max_workers, regions, output):
    """Find unused CloudWatch alarms"""
    from .services.cloudwatch_audit import CloudWatchAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = CloudWatchAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_unused_alarms', output, days=days))

@cloudwatch.command('check-log-retention')
@common_options
@click.pass_context
def cloudwatch_check_logs(ctx, organization, region, max_workers, regions, output):
    """Find log groups without retention policies"""
    from .services.cloudwatch_audit import CloudWatchAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = CloudWatchAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_log_groups_without_retention', output))


@cloudwatch.command('check_unused_custom_metrics')
@click.option('--days', default=30, help='Days threshold for metrics activity')
@common_options
@click.pass_context
def cloudwatch_check_custom_metrics(ctx, days, organization, region, max_workers, regions, output):
    """Find unused custom metrics (no data in X days)"""
    from .services.cloudwatch_audit import CloudWatchAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = CloudWatchAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_unused_custom_metrics', output, days=days))





# DynamoDB Commands
@cli.group()
@click.pass_context
def dynamodb(ctx):
    """DynamoDB operations"""
    pass

@dynamodb.command('audit')
@click.option('--days', default=7, help='Days threshold for idle tables')
@common_options
@click.pass_context
def dynamodb_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run complete DynamoDB audit"""
    from .services.dynamodb_audit import DynamoDBAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = DynamoDBAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output, days=days))

@dynamodb.command('cost-audit')
@click.option('--days', default=7, help='Days threshold for idle tables')
@common_options
@click.pass_context
def dynamodb_cost_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run DynamoDB cost optimization audit only"""
    from .services.dynamodb_audit import DynamoDBAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = DynamoDBAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output, days=days))

@dynamodb.command('security-audit')
@common_options
@click.pass_context
def dynamodb_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run DynamoDB security audit only"""
    from .services.dynamodb_audit import DynamoDBAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = DynamoDBAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output))



@dynamodb.command('find-idle-tables')
@click.option('--days', default=7, help='Days threshold for table activity')
@common_options
@click.pass_context
def dynamodb_find_idle(ctx, days, organization, region, max_workers, regions, output):
    """Find idle DynamoDB tables (alternative method)"""
    from .services.dynamodb_audit import DynamoDBAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = DynamoDBAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('find_idle_tables', output, days=days))

# Route53 Commands
@cli.group()
@click.pass_context
def route53(ctx):
    """Route53 operations"""
    pass

@route53.command('audit')
@common_options
@click.pass_context
def route53_audit(ctx, organization, region, max_workers, regions, output):
    """Run complete Route53 audit"""
    from .services.route53_audit import Route53AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = Route53AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output))

@route53.command('cost-audit')
@common_options
@click.pass_context
def route53_cost_audit(ctx, organization, region, max_workers, regions, output):
    """Run Route53 cost optimization audit only"""
    from .services.route53_audit import Route53AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = Route53AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output))

@route53.command('security-audit')
@common_options
@click.pass_context
def route53_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run Route53 security audit only"""
    from .services.route53_audit import Route53AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = Route53AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output))

@route53.command('check-unused-hosted-zones')
@common_options
@click.pass_context
def route53_check_unused(ctx, organization, region, max_workers, regions, output):
    """Find unused Route53 hosted zones"""
    from .services.route53_audit import Route53AuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = Route53AuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_unused_hosted_zones', output))



# API Gateway Commands
@cli.group()
@click.pass_context
def apigateway(ctx):
    """API Gateway operations"""
    pass

@apigateway.command('audit')
@click.option('--days', default=30, help='Days threshold for unused APIs')
@common_options
@click.pass_context
def apigateway_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run complete API Gateway audit"""
    from .services.apigateway_audit import APIGatewayAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = APIGatewayAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output, days=days))

@apigateway.command('cost-audit')
@click.option('--days', default=30, help='Days threshold for unused APIs')
@common_options
@click.pass_context
def apigateway_cost_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run API Gateway cost optimization audit only"""
    from .services.apigateway_audit import APIGatewayAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = APIGatewayAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output, days=days))

@apigateway.command('security-audit')
@common_options
@click.pass_context
def apigateway_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run API Gateway security audit only"""
    from .services.apigateway_audit import APIGatewayAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = APIGatewayAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output))

@apigateway.command('check-unused-apis')
@click.option('--days', default=30, help='Days threshold for API usage')
@common_options
@click.pass_context
def apigateway_check_unused(ctx, days, organization, region, max_workers, regions, output):
    """Find unused API Gateway APIs"""
    from .services.apigateway_audit import APIGatewayAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = APIGatewayAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_unused_apis', output, days=days))

# Backup Commands
@cli.group()
@click.pass_context
def backup(ctx):
    """AWS Backup operations"""
    pass

@backup.command('audit')
@common_options
@click.pass_context
def backup_audit(ctx, organization, region, max_workers, regions, output):
    """Run complete AWS Backup audit"""
    from .services.backup_audit import BackupAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = BackupAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output))

@backup.command('cost-audit')
@common_options
@click.pass_context
def backup_cost_audit(ctx, organization, region, max_workers, regions, output):
    """Run AWS Backup cost optimization audit only"""
    from .services.backup_audit import BackupAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = BackupAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output))

@backup.command('security-audit')
@common_options
@click.pass_context
def backup_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run AWS Backup security audit only"""
    from .services.backup_audit import BackupAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = BackupAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output))

@backup.command('check-empty-vaults')
@common_options
@click.pass_context
def backup_check_empty(ctx, organization, region, max_workers, regions, output):
    """Find empty backup vaults"""
    from .services.backup_audit import BackupAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = BackupAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_empty_backup_vaults', output))

@backup.command('check-cross-region-backup')
@common_options
@click.pass_context
def backup_check_cross_region(ctx, organization, region, max_workers, regions, output):
    """Find cross-region backup for dev/test"""
    from .services.backup_audit import BackupAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = BackupAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_cross_region_backup_dev_test', output))

# Snapshots Commands
@cli.group()
@click.pass_context
def snapshots(ctx):
    """EBS Snapshots operations"""
    pass

@snapshots.command('audit')
@click.option('--days', default=30, help='Days threshold for old snapshots')
@common_options
@click.pass_context
def snapshots_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run complete EBS Snapshots audit"""
    from .services.snapshots_audit import SnapshotsAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = SnapshotsAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('audit', output, days=days))

@snapshots.command('cost-audit')
@click.option('--days', default=30, help='Days threshold for old snapshots')
@common_options
@click.pass_context
def snapshots_cost_audit(ctx, days, organization, region, max_workers, regions, output):
    """Run EBS Snapshots cost optimization audit only"""
    from .services.snapshots_audit import SnapshotsAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = SnapshotsAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('cost_audit', output, days=days))

@snapshots.command('security-audit')
@common_options
@click.pass_context
def snapshots_security_audit(ctx, organization, region, max_workers, regions, output):
    """Run EBS Snapshots security audit only"""
    from .services.snapshots_audit import SnapshotsAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = SnapshotsAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('security_audit', output))

@snapshots.command('check-old-snapshots')
@click.option('--days', default=30, help='Days threshold for old snapshots')
@common_options
@click.pass_context
def snapshots_check_old(ctx, days, organization, region, max_workers, regions, output):
    """Find old EBS snapshots"""
    from .services.snapshots_audit import SnapshotsAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = SnapshotsAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('check_old_snapshots', output, days=days))

@snapshots.command('find-old-snapshots')
@click.option('--days', default=30, help='Days threshold for old snapshots')
@common_options
@click.pass_context
def snapshots_find_old(ctx, days, organization, region, max_workers, regions, output):
    """Find old EBS snapshots (alternative method)"""
    from .services.snapshots_audit import SnapshotsAuditService
    org, reg_list, workers = get_effective_params(ctx, organization, region, max_workers, regions)
    service = SnapshotsAuditService()
    executor = ServiceExecutor(service, org, reg_list, workers)
    asyncio.run(executor.execute('find_old_snapshots', output, days=days))

# Main audit commands
@cli.command('audit')
@click.option('--organization', is_flag=True, help='Run across organization accounts')
@click.option('--regions', help='Comma-separated list of regions (e.g., us-east-1,eu-west-1)')
@click.option('--region', help='AWS region to scan')
@click.option('--max-workers', type=int, help='Maximum concurrent workers')
@click.option('--output', default='console', type=click.Choice(['console', 'json', 'csv', 'all']), help='Output format')
@click.pass_context
def audit(ctx, organization, region, regions, max_workers, output):
    """Quick comprehensive audit (same as --all)"""
    from .core.scanner import ComprehensiveScanner
    import asyncio
    
    # Use command-level options if provided, otherwise fall back to global options
    org = organization or ctx.obj['organization']
    
    # Handle regions priority
    if regions:
        reg_list = [r.strip() for r in regions.split(',')]
    elif region:
        reg_list = [region]
    elif ctx.obj['region']:
        reg_list = [ctx.obj['region']]
    else:
        reg_list = ['us-east-1']
    
    workers = max_workers or ctx.obj['max_workers']
    
    scanner = ComprehensiveScanner(org, reg_list, workers)
    reporter = asyncio.run(scanner.run_comprehensive_scan())
    
    # Generate reports based on output format
    if output in ['console', 'all']:
        print("\\n" + reporter.generate_summary_report())
    
    if output in ['json', 'all']:
        json_file = reporter.save_json_report()
        print(f"\\n📄 Detailed JSON report saved: {json_file}")
    
    if output in ['csv', 'all']:
        csv_file = reporter.save_csv_report()
        print(f"📊 CSV report saved: {csv_file}")
    
    if output == 'all':
        print(f"\\n🎉 All reports generated successfully!")
        print(f"💰 Total potential monthly savings: ${reporter.total_potential_savings:,}")

if __name__ == '__main__':
    cli()