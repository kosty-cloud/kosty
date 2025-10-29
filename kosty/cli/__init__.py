#!/usr/bin/env python3
import click
import asyncio
from .. import __version__

# Import all service commands
from .ec2_commands import ec2
from .s3_commands import s3
from .rds_commands import rds
from .lambda_commands import lambda_func
from .ebs_commands import ebs
from .iam_commands import iam
from .eip_commands import eip
from .lb_commands import lb
from .nat_commands import nat
from .sg_commands import sg
from .cloudwatch_commands import cloudwatch
from .dynamodb_commands import dynamodb
from .route53_commands import route53
from .apigateway_commands import apigateway
from .backup_commands import backup
from .snapshots_commands import snapshots

@click.group(invoke_without_command=True)
@click.option('--organization', is_flag=True, help='Run across organization accounts')
@click.option('--region', default='us-east-1', help='AWS region')
@click.option('--max-workers', default=5, help='Maximum concurrent workers')
@click.option('--all', 'run_all', is_flag=True, help='Run comprehensive scan of all services')
@click.option('--output', default='console', type=click.Choice(['console', 'json', 'csv', 'all']), help='Output format')
@click.option('--cross-account-role', default='OrganizationAccountAccessRole', help='Role name for cross-account access')
@click.option('--org-admin-account-id', help='Organization admin account ID (if different from current account)')
@click.version_option(version=__version__, prog_name='Kosty')
@click.pass_context
def cli(ctx, run_all, organization, region, max_workers, output, cross_account_role, org_admin_account_id):
    """Kosty - AWS Cost Optimization Tool"""
    ctx.ensure_object(dict)
    ctx.obj['organization'] = organization
    ctx.obj['region'] = region
    ctx.obj['max_workers'] = max_workers
    ctx.obj['cross_account_role'] = cross_account_role
    ctx.obj['org_admin_account_id'] = org_admin_account_id
    
    if run_all:
        from ..core.scanner import ComprehensiveScanner
        import asyncio
        
        scanner = ComprehensiveScanner(organization, region, max_workers, cross_account_role, org_admin_account_id)
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

# Main audit command
@cli.command('audit')
@click.option('--organization', is_flag=True, help='Run across organization accounts')
@click.option('--regions', help='Comma-separated list of regions (e.g., us-east-1,eu-west-1)')
@click.option('--region', help='AWS region to scan')
@click.option('--max-workers', type=int, help='Maximum concurrent workers')
@click.option('--output', default='console', type=click.Choice(['console', 'json', 'csv', 'all']), help='Output format')
@click.option('--cross-account-role', help='Role name for cross-account access')
@click.option('--org-admin-account-id', help='Organization admin account ID')
@click.pass_context
def audit(ctx, organization, region, regions, max_workers, output, cross_account_role, org_admin_account_id):
    """Quick comprehensive audit (same as --all)"""
    from ..core.scanner import ComprehensiveScanner
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
    role_name = cross_account_role or ctx.obj['cross_account_role']
    admin_account = org_admin_account_id or ctx.obj['org_admin_account_id']
    
    scanner = ComprehensiveScanner(org, reg_list, workers, role_name, admin_account)
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
        total_issues = sum(sum(cmd['count'] for cmd in svc.values()) for acc in reporter.results.values() for svc in acc.values())
        print(f"📊 Total issues found: {total_issues}")

# Version command
@cli.command()
def version():
    """Show Kosty version"""
    click.echo(f"Kosty v{__version__}")

# Add all service commands to the main CLI
cli.add_command(ec2)
cli.add_command(s3)
cli.add_command(rds)
cli.add_command(lambda_func)
cli.add_command(ebs)
cli.add_command(iam)
cli.add_command(eip)
cli.add_command(lb)
cli.add_command(nat)
cli.add_command(sg)
cli.add_command(cloudwatch)
cli.add_command(dynamodb)
cli.add_command(route53)
cli.add_command(apigateway)
cli.add_command(backup)
cli.add_command(snapshots)

if __name__ == '__main__':
    cli()