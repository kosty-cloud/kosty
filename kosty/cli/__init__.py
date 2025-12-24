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
@click.option('--config-file', help='Path to configuration file (default: ./kosty.yaml or ~/.kosty/config.yaml)')
@click.option('--profile', default='default', help='Configuration profile to use')
@click.option('--organization', is_flag=True, help='Run across organization accounts')
@click.option('--region', default='us-east-1', help='AWS region')
@click.option('--max-workers', default=5, help='Maximum concurrent workers')
@click.option('--all', 'run_all', is_flag=True, help='Run comprehensive scan of all services')
@click.option('--output', default='console', type=click.Choice(['console', 'json', 'csv', 'all']), help='Output format')
@click.option('--cross-account-role', default='OrganizationAccountAccessRole', help='Role name for cross-account access')
@click.option('--org-admin-account-id', help='Organization admin account ID (if different from current account)')
@click.version_option(version=__version__, prog_name='Kosty')
@click.pass_context
def cli(ctx, config_file, profile, run_all, organization, region, max_workers, output, cross_account_role, org_admin_account_id):
    """Kosty - AWS Cost Optimization Tool"""
    ctx.ensure_object(dict)
    ctx.obj['config_file'] = config_file
    ctx.obj['profile'] = profile
    ctx.obj['organization'] = organization
    ctx.obj['region'] = region
    ctx.obj['max_workers'] = max_workers
    ctx.obj['cross_account_role'] = cross_account_role
    ctx.obj['org_admin_account_id'] = org_admin_account_id
    
    if run_all:
        from ..core.scanner import ComprehensiveScanner
        from ..core.config import ConfigManager
        import asyncio
        
        try:
            config_manager = ConfigManager(
                config_file=config_file,
                profile=profile
            )
            session = config_manager.get_aws_session()
        except Exception:
            config_manager = None
            session = None
        
        scanner = ComprehensiveScanner(organization, region, max_workers, cross_account_role, org_admin_account_id, config_manager=config_manager, session=session)
        reporter = asyncio.run(scanner.run_comprehensive_scan())
        
        # Generate reports based on output format
        if output in ['console', 'all']:
            print(reporter.generate_summary_report())
        
        if output in ['json', 'all']:
            json_file = reporter.save_json_report(organization=organization, org_admin_account_id=org_admin_account_id)
            print(f"\\n📄 Detailed JSON report saved: {json_file}")
        
        if output in ['csv', 'all']:
            csv_file = reporter.save_csv_report(organization=organization, org_admin_account_id=org_admin_account_id)
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
@click.option('--profile', help='Configuration profile to use')
@click.option('--organization', is_flag=True, help='Run across organization accounts')
@click.option('--regions', help='Comma-separated list of regions (e.g., us-east-1,eu-west-1)')
@click.option('--region', help='AWS region to scan')
@click.option('--max-workers', type=int, help='Maximum concurrent workers')
@click.option('--output', default='console', type=click.Choice(['console', 'json', 'csv', 'all']), help='Output format')
@click.option('--save-to', help='Save output to S3 (s3://bucket/path) or local path (/path/to/file)')
@click.option('--cross-account-role', help='Role name for cross-account access')
@click.option('--org-admin-account-id', help='Organization admin account ID')
@click.option('--profiles', is_flag=True, help='Run audit on all profiles from config file')
@click.option('--max-parallel-profiles', type=int, default=3, help='Max profiles to run in parallel (default: 3)')
@click.pass_context
def audit(ctx, profile, organization, region, regions, max_workers, output, save_to, cross_account_role, org_admin_account_id, profiles, max_parallel_profiles):
    """Quick comprehensive audit (same as --all)"""
    from ..core.scanner import ComprehensiveScanner
    from ..core.config import ConfigManager
    from ..core.multi_profile_runner import MultiProfileRunner
    import asyncio
    
    # Multi-profile mode
    if profiles:
        runner = MultiProfileRunner(config_file=ctx.obj.get('config_file'))
        
        cli_args = {
            'organization': organization,
            'region': region,
            'regions': regions,
            'max_workers': max_workers,
            'output': output,
            'save_to': save_to,
            'cross_account_role': cross_account_role,
            'org_admin_account_id': org_admin_account_id
        }
        
        runner.run_parallel(cli_args, max_parallel=max_parallel_profiles)
        
        if output in ['console', 'all']:
            runner.print_summary()
        
        if output in ['json', 'csv', 'all']:
            runner.save_reports(output_format=output)
        
        return
    
    # Single profile mode (existing logic)
    profile_name = profile or ctx.obj.get('profile', 'default')
    try:
        config_manager = ConfigManager(
            config_file=ctx.obj.get('config_file'),
            profile=profile_name
        )
    except Exception as e:
        print(f"\n❌ Configuration error: {e}")
        return
    
    # Merge config with CLI args (CLI takes priority)
    final_config = config_manager.merge_with_cli_args({
        'organization': organization,
        'region': region,
        'regions': regions,
        'max_workers': max_workers,
        'output': output,
        'save_to': save_to,
        'cross_account_role': cross_account_role,
        'org_admin_account_id': org_admin_account_id
    })
    
    # Handle regions priority
    if final_config.get('regions'):
        if isinstance(final_config['regions'], str):
            reg_list = [r.strip() for r in final_config['regions'].split(',')]
        else:
            reg_list = final_config['regions']
    elif final_config.get('region'):
        reg_list = [final_config['region']]
    else:
        reg_list = ['us-east-1']
    
    # Get AWS session (with AssumeRole/MFA if configured)
    session = config_manager.get_aws_session()
    
    # Validate save location upfront if specified
    if final_config.get('save_to') and final_config.get('output') in ['json', 'csv', 'all']:
        from ..core.storage import StorageManager
        storage_manager = StorageManager()
        print(f"\n🔍 Validating save location: {final_config['save_to']}")
        if not asyncio.run(storage_manager.validate_save_location(final_config['save_to'])):
            print("\n🛑 Save location validation failed. Aborting scan.")
            return
        print("✅ Save location validated successfully")
    
    scanner = ComprehensiveScanner(
        final_config.get('organization', False),
        reg_list,
        final_config.get('max_workers', 5),
        final_config.get('cross_account_role', 'OrganizationAccountAccessRole'),
        final_config.get('org_admin_account_id'),
        config_manager=config_manager,
        session=session
    )
    reporter = asyncio.run(scanner.run_comprehensive_scan())
    
    # Generate reports based on output format
    if output in ['console', 'all']:
        print("\\n" + reporter.generate_summary_report())
    
    if output in ['json', 'all']:
        json_file = asyncio.run(reporter.save_json_report(organization=final_config.get('organization', False), org_admin_account_id=final_config.get('org_admin_account_id'), save_to=save_to))
        print(f"\\n📄 Detailed JSON report saved: {json_file}")
    
    if output in ['csv', 'all']:
        csv_file = asyncio.run(reporter.save_csv_report(organization=final_config.get('organization', False), org_admin_account_id=final_config.get('org_admin_account_id'), save_to=save_to))
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