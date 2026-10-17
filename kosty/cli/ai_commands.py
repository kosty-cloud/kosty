import json
import json
import sys
from datetime import datetime

import click

from .utils import (
    common_options,
    execute_engine_command,
    _ensure_plugins_loaded,
    _resolve_scan_params,
    _serialize_findings_csv,
    _persist_report,
)


def _run_combined_ai_audit(ctx, method, output, save_to, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, **kwargs):
    """Run Bedrock + SageMaker through the engine, merge results, output once."""
    from ..core.engine import ScanEngine
    from ..core.models import FindingType

    session, reg_list, workers, config_manager = _resolve_scan_params(
        ctx, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id
    )

    debug = ctx.obj.get('debug', False) if ctx.obj else False
    verbose = ctx.obj.get('verbose', False) if ctx.obj else False
    allow_outside_cwd = bool(ctx.obj.get('allow_outside_cwd')) if ctx.obj else False
    if config_manager and config_manager.get('save_to_allow_outside', False):
        allow_outside_cwd = True

    if config_manager:
        reg_list = [r for r in reg_list if not config_manager.should_exclude_region(r)]

    strict_plugins = bool(config_manager.get('strict_plugins', False)) if config_manager else False
    _ensure_plugins_loaded(strict=strict_plugins, debug=debug)

    finding_type_filter = None
    if method == 'cost_audit':
        finding_type_filter = FindingType.COST
    elif method == 'security_audit':
        finding_type_filter = FindingType.SECURITY

    engine = ScanEngine(max_workers=workers)

    all_findings = []
    all_errors = []
    for service_name in ['Bedrock', 'SageMaker']:
        result = engine.run_service(
            session, reg_list,
            service=service_name,
            finding_type=finding_type_filter,
            config_manager=config_manager,
            debug=debug,
            **kwargs,
        )
        print(f"\n🤖 {service_name} Audit: {len(result.findings)} issues")
        all_findings.extend(result.findings)
        all_errors.extend(result.errors)

    if config_manager:
        all_findings = [
            f for f in all_findings
            if not (f.arn and config_manager.should_exclude_arn(f.arn))
        ]

    if all_errors:
        print(
            f"\n⚠️  {len(all_errors)} check(s) could not complete (e.g. missing"
            f" permissions); re-run with --debug for per-check details.",
            file=sys.stderr,
        )

    total = len(all_findings)
    items = [f.to_dict() for f in all_findings]

    if output in ['console', 'all']:
        if total > 0:
            print(f"\n{'─' * 50}")
            for item in items:
                sev_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}.get(item.get('severity', ''), '⚪')
                print(f"  {sev_icon} [{item.get('Service')}] {item.get('Issue')}")
                print(f"     Resource: {item.get('ResourceId', '')} ({item.get('Region', '')})")
                if verbose:
                    if item.get('Risk'):
                        print(f"     Risk: {item['Risk']}")
                    if item.get('ARN'):
                        print(f"     ARN: {item['ARN']}")
                    savings = item.get('monthly_savings') or item.get('MonthlySavings')
                    if savings:
                        print(f"     Savings: ${savings:.2f}/mo")
                    if item.get('check'):
                        print(f"     Check: {item['check']}")

    if output in ['json', 'all']:
        from ..core.exceptions import SaveLocationError
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        account_id = items[0].get('AccountId', 'unknown') if items else 'unknown'
        filename = f"kosty_ai_{account_id}_{timestamp}.json"
        # AI report shape is preserved (method + results keyed by account).
        report = {'scan_timestamp': datetime.now().isoformat(), 'method': f'ai_{method}', 'total_issues': total, 'results': {account_id: items}}
        content = json.dumps(report, indent=2, default=str)
        try:
            dest = _persist_report(content, filename, save_to, 'json', allow_outside_cwd)
        except SaveLocationError as e:
            print(f"\n❌ {e}", file=sys.stderr)
            return
        print(f"\n📄 AI audit JSON report saved: {dest}")

    if output in ['csv', 'all']:
        from ..core.exceptions import SaveLocationError
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        account_id = items[0].get('AccountId', 'unknown') if items else 'unknown'
        filename = f"kosty_ai_{account_id}_{timestamp}.csv"
        if items:
            content = _serialize_findings_csv(items)
            try:
                dest = _persist_report(content, filename, save_to, 'csv', allow_outside_cwd)
            except SaveLocationError as e:
                print(f"\n❌ {e}", file=sys.stderr)
                return
            print(f"📊 AI audit CSV report saved: {dest}")

    print(f"\n🎯 AI Audit Total: {total} issues (Bedrock + SageMaker)")


@click.group(name='ai')
@click.pass_context
def ai_audit(ctx):
    """AI/ML audit — Bedrock + SageMaker cost & security"""
    pass


# --- Top-level ai commands (runs both services) ---

@ai_audit.command('audit')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def ai_full_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run full AI audit (Bedrock + SageMaker)"""
    _run_combined_ai_audit(ctx, 'audit', output, save_to, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, days=days)


@ai_audit.command('cost-audit')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def ai_cost_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run AI cost audit (Bedrock + SageMaker)"""
    _run_combined_ai_audit(ctx, 'cost_audit', output, save_to, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, days=days)


@ai_audit.command('security-audit')
@common_options
@click.pass_context
def ai_security_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run AI security audit (Bedrock + SageMaker)"""
    _run_combined_ai_audit(ctx, 'security_audit', output, save_to, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id)


# --- Bedrock subgroup ---

@ai_audit.group()
@click.pass_context
def bedrock(ctx):
    """Bedrock audit commands"""
    pass


@bedrock.command('audit')
@common_options
@click.pass_context
def bedrock_audit(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run full Bedrock audit"""
    execute_engine_command(ctx, 'Bedrock', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('cost-audit')
@common_options
@click.pass_context
def bedrock_cost(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Bedrock cost audit"""
    execute_engine_command(ctx, 'Bedrock', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('security-audit')
@common_options
@click.pass_context
def bedrock_security(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run Bedrock security audit"""
    execute_engine_command(ctx, 'Bedrock', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@bedrock.command('check-no-logging')
@common_options
@click.pass_context
def bedrock_check_logging(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if Bedrock invocation logging is enabled"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-001')


@bedrock.command('check-no-budget-limits')
@common_options
@click.pass_context
def bedrock_check_budget(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if AWS Budget exists for Bedrock spend"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-002')


@bedrock.command('check-no-guardrails')
@common_options
@click.pass_context
def bedrock_check_guardrails(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if Bedrock Guardrails are configured"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-003')


@bedrock.command('check-shadow-ai')
@common_options
@click.pass_context
def bedrock_check_shadow(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find IAM roles with AI permissions not tagged as approved"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-004')


@bedrock.command('check-no-vpc-endpoint')
@common_options
@click.pass_context
def bedrock_check_vpc(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if VPC endpoint exists for Bedrock"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-005')


@bedrock.command('check-custom-model-no-kms')
@common_options
@click.pass_context
def bedrock_check_kms(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if custom models are encrypted with customer-managed KMS"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-006')


@bedrock.command('check-no-prompt-caching')
@common_options
@click.pass_context
def bedrock_check_caching(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if prompt caching is being used"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-007')


@bedrock.command('check-no-inference-profiles')
@common_options
@click.pass_context
def bedrock_check_profiles(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if Application Inference Profiles are configured"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-008')


@bedrock.command('check-tpm-quota')
@common_options
@click.pass_context
def bedrock_check_tpm(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if Bedrock TPM quota usage is above 80%"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-009')


@bedrock.command('check-cross-account-model-access')
@common_options
@click.pass_context
def bedrock_check_cross_account(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check S3 bucket policies on custom model training data for cross-account access"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-010')


@bedrock.command('check-model-sizing')
@click.option('--deep', is_flag=True, help='Analyze CloudWatch Logs to detect premium models used for simple tasks')
@click.option('--days', default=7, type=int, help='Days of logs to analyze (default: 7)')
@common_options
@click.pass_context
def bedrock_check_model_sizing(ctx, deep, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Detect premium models used for simple tasks (requires --deep)"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-011', deep=deep, days=days)


@bedrock.command('check-batch-eligible')
@click.option('--deep', is_flag=True, help='Analyze CloudWatch Logs to detect batch-eligible workloads')
@click.option('--days', default=7, type=int, help='Days of logs to analyze (default: 7)')
@common_options
@click.pass_context
def bedrock_check_batch(ctx, deep, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Detect On-Demand workloads eligible for Batch Inference API (requires --deep)"""
    execute_engine_command(ctx, 'Bedrock', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-bedrock-012', deep=deep, days=days)


# --- SageMaker subgroup ---

@ai_audit.group()
@click.pass_context
def sagemaker(ctx):
    """SageMaker audit commands"""
    pass


@sagemaker.command('audit')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def sagemaker_audit(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run full SageMaker audit"""
    execute_engine_command(ctx, 'SageMaker', 'audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@sagemaker.command('cost-audit')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def sagemaker_cost(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SageMaker cost audit"""
    execute_engine_command(ctx, 'SageMaker', 'cost_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, days=days)


@sagemaker.command('security-audit')
@common_options
@click.pass_context
def sagemaker_security(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Run SageMaker security audit"""
    execute_engine_command(ctx, 'SageMaker', 'security_audit', output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile)


@sagemaker.command('check-idle-endpoints')
@click.option('--days', default=7, type=int, help='Days threshold for idle endpoints (default: 7)')
@common_options
@click.pass_context
def sagemaker_check_idle(ctx, days, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find endpoints with zero invocations"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-001', days=days)


@sagemaker.command('check-zombie-notebooks')
@common_options
@click.pass_context
def sagemaker_check_notebooks(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find running notebook instances"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-002')


@sagemaker.command('check-no-spot-training')
@common_options
@click.pass_context
def sagemaker_check_spot(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find training jobs not using Spot instances"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-003')


@sagemaker.command('check-no-checkpointing')
@common_options
@click.pass_context
def sagemaker_check_checkpoint(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find Spot training jobs without checkpointing"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-004')


@sagemaker.command('check-no-vpc-endpoint')
@common_options
@click.pass_context
def sagemaker_check_vpc(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Check if VPC endpoint exists for SageMaker"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-005')


@sagemaker.command('check-notebook-direct-internet')
@common_options
@click.pass_context
def sagemaker_check_internet(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find notebooks with direct internet access"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-006')


@sagemaker.command('check-notebook-root-access')
@common_options
@click.pass_context
def sagemaker_check_root(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find notebooks with root access enabled"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-007')


@sagemaker.command('check-no-inference-components')
@common_options
@click.pass_context
def sagemaker_check_ic(ctx, profile, organization, region, max_workers, regions, output, save_to, cross_account_role, org_admin_account_id):
    """Find GPU endpoints not using Inference Components (multi-model packing)"""
    execute_engine_command(ctx, 'SageMaker', None, output, organization, region, max_workers, regions, cross_account_role, org_admin_account_id, save_to, profile, check_id='aws-sagemaker-008')
