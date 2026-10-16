"""Shared utilities for all CLI service commands.

The key entry point here is execute_engine_command(), which every service
command calls. It handles config resolution, plugin loading, check selection,
execution, and output in one place so individual command files stay thin.
"""

import click
import json
import os
from datetime import datetime
from ..core.config import ConfigManager, DEFAULT_MAX_WORKERS


def _debug_callback(ctx, param, value):
    """Store debug flag in ctx.obj so execute_engine_command can read it
    without requiring every command function to forward it explicitly.
    """
    if ctx.obj is None:
        ctx.obj = {}
    ctx.obj['debug'] = value
    return value


def _verbose_callback(ctx, param, value):
    """Store verbose flag in ctx.obj so execute_engine_command can read it
    without requiring every command function to forward it explicitly.
    """
    if ctx.obj is None:
        ctx.obj = {}
    ctx.obj['verbose'] = value
    return value


def _allow_outside_cwd_callback(ctx, param, value):
    """Store the save-to opt-out in ctx.obj so execute_engine_command can read
    it without requiring every service command to forward it explicitly.
    """
    if ctx.obj is None:
        ctx.obj = {}
    ctx.obj['allow_outside_cwd'] = value
    return value


def common_options(f):
    """Decorator that attaches the standard scan options to any Click command.

    Applied to every service command so the option set stays consistent
    across all 30+ commands without repeating the definitions.
    """
    f = click.option('--profile', help='Configuration profile to use')(f)
    f = click.option('--output', default='console', type=click.Choice(['console', 'json', 'csv']), help='Output format')(f)
    f = click.option('--save-to', help='Save output to S3 (s3://bucket/path) or local path (/path/to/file)')(f)
    f = click.option('--allow-outside-cwd', is_flag=True, expose_value=False,
                     callback=_allow_outside_cwd_callback, is_eager=False,
                     help='Permit --save-to local paths outside the current working directory')(f)
    f = click.option('--regions', help='Comma-separated list of regions (e.g., us-east-1,eu-west-1)')(f)
    f = click.option('--max-workers', default=DEFAULT_MAX_WORKERS, help='Maximum number of worker threads')(f)
    f = click.option('--region', help='AWS region to scan')(f)
    f = click.option('--organization', is_flag=True, help='Scan entire AWS organization')(f)
    f = click.option('--cross-account-role', default='OrganizationAccountAccessRole', help='Role name for cross-account access')(f)
    f = click.option('--org-admin-account-id', help='Organization admin account ID (if different from current account)')(f)
    f = click.option('--verbose', is_flag=True, expose_value=False, callback=_verbose_callback, is_eager=False,
                     help='Show full finding details (ARN, risk, savings, check ID)')(f)
    f = click.option('--debug', is_flag=True, expose_value=False, callback=_debug_callback, is_eager=False,
                     help='Print check execution details, errors, and timing to stderr')(f)
    return f

def _resolve_scan_params(ctx, profile, organization, region, max_workers, regions, cross_account_role, org_admin_account_id):
    """Resolve session, region list, and worker count from CLI args + config.

    Config file values are the baseline; CLI args take priority.
    Falls back to a plain boto3.Session() with the CLI-provided region
    if config loading fails (e.g. malformed kosty.yaml).
    """
    import boto3
    profile_name = profile or ctx.obj.get('profile', 'default')
    try:
        config_manager = ConfigManager(
            config_file=ctx.obj.get('config_file'),
            profile=profile_name
        )
        session = config_manager.get_aws_session()
        final = config_manager.merge_with_cli_args({
            'organization': organization, 'region': region, 'regions': regions,
            'max_workers': max_workers, 'cross_account_role': cross_account_role,
            'org_admin_account_id': org_admin_account_id
        })
        if final.get('regions'):
            reg_list = [r.strip() for r in final['regions'].split(',')] if isinstance(final['regions'], str) else final['regions']
        elif final.get('region'):
            reg_list = [final['region']]
        else:
            reg_list = ['us-east-1']
        return session, reg_list, final.get('max_workers', DEFAULT_MAX_WORKERS), config_manager
    except Exception:
        if regions:
            reg_list = [r.strip() for r in regions.split(',')]
        elif region:
            reg_list = [region]
        elif ctx.obj.get('region'):
            reg_list = [ctx.obj['region']]
        else:
            reg_list = ['us-east-1']
        return boto3.Session(), reg_list, max_workers or ctx.obj.get('max_workers', DEFAULT_MAX_WORKERS), None


def _run_checks(checks, session, reg_list, workers, config_manager, debug=False, **kwargs):
    """Execute a list of checks across regions and return (findings, errors).

    Injects compliance_ids from check metadata into each finding so plugins
    don't need to repeat the mapping in their Finding constructors.

    A check that raises is recorded as an (check_id, region, exc_type, message)
    tuple in the returned errors list instead of being silently swallowed, so
    the caller can surface a count to the user without requiring --debug.
    """
    import sys
    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed

    all_findings = []
    errors = []
    for rgn in reg_list:
        if debug:
            print(f"[DEBUG] region={rgn} checks={len(checks)}", file=sys.stderr)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(c['func'], session=session, region=rgn,
                                config_manager=config_manager, **kwargs): c
                for c in checks
            }
            for future in as_completed(futures):
                check = futures[future]
                t0 = time.monotonic()
                try:
                    result = future.result()
                    if isinstance(result, list):
                        if check['metadata'].compliance_ids:
                            for f in result:
                                if hasattr(f, 'compliance_ids') and not f.compliance_ids:
                                    f.compliance_ids = check['metadata'].compliance_ids
                        all_findings.extend(result)
                        if debug:
                            elapsed = time.monotonic() - t0
                            print(
                                f"[DEBUG] {check['metadata'].check_id} {rgn}"
                                f" findings={len(result)} t={elapsed:.2f}s",
                                file=sys.stderr,
                            )
                except Exception as e:
                    errors.append((check['metadata'].check_id, rgn, type(e).__name__, str(e)))
                    if debug:
                        elapsed = time.monotonic() - t0
                        print(
                            f"[DEBUG] {check['metadata'].check_id} {rgn}"
                            f" ERROR {type(e).__name__}: {e} t={elapsed:.2f}s",
                            file=sys.stderr,
                        )
    return all_findings, errors


def execute_engine_command(ctx, service_name, method, output, organization, region,
                           max_workers, regions, cross_account_role=None,
                           org_admin_account_id=None, save_to=None, profile=None,
                           check_id=None, allow_outside_cwd=False, **kwargs):
    """Resolve config, select checks, run them, and display results."""
    import sys
    verbose = ctx.obj.get('verbose', False) if ctx.obj else False
    debug = ctx.obj.get('debug', False) if ctx.obj else False
    if ctx.obj and ctx.obj.get('allow_outside_cwd'):
        allow_outside_cwd = True
    from ..core.registry import registry
    from ..core.models import FindingType

    session, reg_list, workers, config_manager = _resolve_scan_params(
        ctx, profile, organization, region, max_workers, regions,
        cross_account_role, org_admin_account_id
    )

    # The opt-out is enabled by either the CLI flag or the config key.
    if config_manager and config_manager.get('save_to_allow_outside', False):
        allow_outside_cwd = True

    if config_manager:
        reg_list = [r for r in reg_list if not config_manager.should_exclude_region(r)]

    strict_plugins = bool(config_manager.get('strict_plugins', False)) if config_manager else False
    _ensure_plugins_loaded(strict=strict_plugins, debug=debug)

    if check_id:
        entry = registry.get_check(check_id)
        checks = [entry] if entry else []
    else:
        checks = registry.get_checks_by_service(service_name)
        if method == 'cost_audit':
            checks = [c for c in checks if c['metadata'].finding_type == FindingType.COST]
        elif method == 'security_audit':
            checks = [c for c in checks if c['metadata'].finding_type == FindingType.SECURITY]

    deep = kwargs.get('deep', False)
    if not deep:
        checks = [c for c in checks if not c['metadata'].requires_deep]

    if debug:
        print(
            f"[DEBUG] service={service_name} method={method or check_id}"
            f" checks={len(checks)} regions={reg_list} workers={workers}",
            file=sys.stderr,
        )

    findings, errors = _run_checks(checks, session, reg_list, workers, config_manager, debug=debug, **kwargs)

    if errors:
        print(
            f"\n⚠️  {len(errors)} check(s) could not complete (e.g. missing"
            f" permissions); re-run with --debug for per-check details.",
            file=sys.stderr,
        )

    if config_manager:
        findings = [
            f for f in findings
            if not (f.arn and config_manager.should_exclude_arn(f.arn))
        ]

    _output_findings(findings, service_name, output, save_to, verbose=verbose,
                     allow_outside_cwd=allow_outside_cwd)


def _ensure_plugins_loaded(strict: bool = False, debug: bool = False):
    """Load native plugins if not already loaded.

    Args:
        strict: Refuse plugins absent from the manifest (opt-in fail-closed).
        debug: Forward per-module load output to stderr.

    Loader warnings and registry warnings are routed to stderr so they
    surface outside --debug.
    """
    import sys
    from ..core.registry import registry
    if registry.count > 0:
        return
    from ..core.loader import PluginLoader
    loader = PluginLoader()
    plugins_dir = os.path.join(os.path.dirname(__file__), '..', 'providers', 'aws', 'services')
    plugins_dir = os.path.abspath(plugins_dir)
    if os.path.isdir(plugins_dir):
        loader.load_directory(plugins_dir, strict=strict, debug=debug)
        for warning in loader.warnings:
            print(f"⚠️  plugin loader: {warning}", file=sys.stderr)
        for warning in registry.warnings:
            print(f"⚠️  registry: {warning}", file=sys.stderr)


_SEVERITY_ICONS = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}


def render_finding_lines(item, service=None, verbose=False):
    """Return the console lines for a single finding dict.

    Shared by the per-service command output (_output_findings) and the
    `kosty audit --verbose` block (_print_verbose_findings) so the layout
    stays identical. When `service` is given it appears in the header; the
    detail block (ARN, savings, check id) is emitted when `verbose` is set.
    """
    icon = _SEVERITY_ICONS.get(item.get('severity', ''), '⚪')
    severity = item.get('severity', '').upper()
    issue = item.get('Issue', '')
    if service:
        lines = [f"  {icon} [{severity}] [{service.upper()}] {issue}"]
    else:
        lines = [f"  {icon} [{severity}] {issue}"]
    lines.append(f"     Resource: {item.get('ResourceId', '')} ({item.get('Region', '')})")
    if item.get('Risk'):
        lines.append(f"     Risk: {item['Risk']}")
    if verbose:
        if item.get('ARN'):
            lines.append(f"     ARN: {item['ARN']}")
        savings = item.get('monthly_savings') or item.get('MonthlySavings')
        if savings:
            lines.append(f"     Savings: ${savings:.2f}/mo")
        if item.get('check'):
            lines.append(f"     Check: {item['check']}")
    return lines


def _output_findings(findings, service_name, output, save_to=None, verbose=False,
                     allow_outside_cwd=False):
    """Display findings in the requested format.

    Local --save-to paths are confined to the current working directory
    unless allow_outside_cwd is set (CLI --allow-outside-cwd or the
    save_to_allow_outside config key).
    """
    import sys
    from ..core.storage import confine_local_path
    from ..core.exceptions import SaveLocationError
    items = [f.to_dict() for f in findings]
    total = len(items)

    if output == 'console' or output == 'all':
        if total == 0:
            print(f"\n✅ {service_name.upper()}: No issues found")
        else:
            print(f"\n🔍 {service_name.upper()}: {total} issues found")
            print("─" * 50)
            for item in items:
                for line in render_finding_lines(item, verbose=verbose):
                    print(line)

    if output in ['json', 'all']:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        account_id = items[0].get('AccountId', 'unknown') if items else 'unknown'
        filename = f"kosty_{service_name}_{account_id}_{timestamp}.json"
        if save_to:
            try:
                dest = confine_local_path(save_to, allow_outside_cwd=allow_outside_cwd)
            except SaveLocationError as e:
                print(f"\n❌ {e}", file=sys.stderr)
                return
            dest.mkdir(parents=True, exist_ok=True)
            filename = str(dest / filename)
        report = {'scan_timestamp': datetime.now().isoformat(), 'service': service_name, 'total_issues': total, 'results': items}
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n📄 JSON report saved: {filename}")

    if output in ['csv', 'all']:
        import csv
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        account_id = items[0].get('AccountId', 'unknown') if items else 'unknown'
        filename = f"kosty_{service_name}_{account_id}_{timestamp}.csv"
        if save_to:
            try:
                dest = confine_local_path(save_to, allow_outside_cwd=allow_outside_cwd)
            except SaveLocationError as e:
                print(f"\n❌ {e}", file=sys.stderr)
                return
            dest.mkdir(parents=True, exist_ok=True)
            filename = str(dest / filename)
        if items:
            from ..core.reporter import sanitize_csv_field
            fieldnames = sorted(set().union(*(item.keys() for item in items)))
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for item in items:
                    writer.writerow({k: sanitize_csv_field(v) for k, v in item.items()})
            print(f"📊 CSV report saved: {filename}")