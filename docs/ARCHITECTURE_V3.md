# Kosty v3.0.0 — Plugin Architecture

## Overview

Kosty v3 introduces a plugin-based scan engine. The core is now an importable library that discovers, loads, and executes checks from any directory. This decouples the scan logic from the CLI and enables:

- **Pro integration** — import the engine, inject a session, get JSON results
- **Premium gating** — load additional plugin paths for paid features
- **Progressive migration** — legacy services work alongside native plugins via an adapter

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                             │
│  (kosty audit, kosty ai, kosty public-exposure)             │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                      ScanEngine                               │
│  - Loads plugins from one or more directories                │
│  - Queries the CheckRegistry                                 │
│  - Executes checks in parallel (ThreadPoolExecutor)          │
│  - Returns ScanResult (list of Findings)                     │
└──────────────────────────┬──────────────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
┌─────────▼────┐  ┌───────▼──────┐  ┌──────▼───────┐
│ CheckRegistry │  │ PluginLoader │  │    Bridge    │
│ (singleton)   │  │ (importlib)  │  │ (legacy CLI) │
└─────────┬────┘  └───────┬──────┘  └──────────────┘
          │                │
          │    ┌───────────▼───────────────────────┐
          │    │        Plugin Sources              │
          │    │                                    │
          │    │  providers/aws/services/  (native) │
          │    │  kosty/services/ (legacy adapter)  │
          │    │  /opt/pro/plugins/ (premium, opt)  │
          │    └────────────────────────────────────┘
          │
┌─────────▼──────────────────────────────────────────┐
│              Registered Checks                       │
│  aws-cloudtrail-001, aws-guardduty-001, ...         │
│  150 native checks across 31 services               │
└─────────────────────────────────────────────────────┘
```

## Key Components

### CheckRegistry (`kosty/core/registry.py`)

Global singleton. Checks self-register at import time via the `@register_check` decorator.

```python
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity

@register_check(
    check_id="aws-s3-001",
    service="S3",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Detect publicly readable S3 buckets",
)
def check_public_read(session, region, **kwargs):
    findings = []
    # ... boto3 logic ...
    findings.append(Finding(
        check_id="aws-s3-001",
        service="S3",
        resource_id=bucket_name,
        region=region,
        account_id=account_id,
        issue="Public read access enabled",
        severity=Severity.CRITICAL,
        finding_type=FindingType.SECURITY,
        risk="Data breach — complete bucket exposure",
    ))
    return findings
```

### PluginLoader (`kosty/core/loader.py`)

Recursively imports `.py` files from a directory. On import, decorated functions register themselves. Supports multiple paths for OSS/Pro gating.

```python
from kosty.core.engine import ScanEngine

engine = ScanEngine()
engine.load_plugins('providers/aws/services')        # OSS checks
engine.load_plugins('/opt/kosty-pro/plugins')        # Premium (if present)
```

### ScanEngine (`kosty/core/engine.py`)

The importable core. No CLI dependency. Runs checks in parallel and returns structured results.

```python
from kosty.core.engine import ScanEngine
from providers.aws.adapter import adapt_all_legacy_services

engine = ScanEngine(max_workers=20)
engine.load_plugins('providers/aws/services')
adapt_all_legacy_services('kosty/services')

result = engine.run(
    session=boto3.Session(),
    regions=['eu-west-3', 'us-east-1'],
    services=['iam', 's3'],  # optional filter
    deep=True,
)

print(result.total_issues)
print(result.total_savings)
for finding in result.findings:
    print(finding.to_dict())
```

### Service Adapter (`providers/aws/adapter.py`)

Wraps legacy `*_audit.py` files into the registry without modifying them. Each `find_*` method becomes a registered check with an auto-generated ID (e.g., `aws-iam-001`).

### Data Models (`kosty/core/models.py`)

- `Finding` — single audit finding (replaces legacy issue dicts)
- `CheckMetadata` — describes a registered check
- `ScanResult` — aggregated scan output
- `Severity` / `FindingType` — enums for type safety

### Provider Interface (`kosty/core/provider.py`)

Abstract base class. Each cloud provider implements `get_session()`, `get_regions()`, `get_account_id()`. Currently only AWS is implemented.

## Writing a New Plugin

### Step 1: Create the directory

```
kosty/providers/aws/services/my_service/
├── __init__.py                    # empty file
└── check_something.py             # one check per file
```

### Step 2: Write the check

```python
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-myservice-001",       # unique across all plugins
    service="MyService",                 # groups checks in CLI output
    provider="aws",                      # provider filter
    finding_type=FindingType.SECURITY,   # SECURITY or COST
    description="Short description for CLI help",
)
def check_something(session, region, **kwargs):
    """One-line docstring explaining what this flags."""
    client = session.client('myservice', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        resources = client.list_resources()
        for resource in resources.get('Items', []):
            if resource_is_bad(resource):
                findings.append(Finding(
                    check_id="aws-myservice-001",
                    service="MyService",
                    resource_id=resource['Id'],
                    region=region,
                    account_id=account_id,
                    issue="What is wrong",
                    severity=Severity.HIGH,
                    finding_type=FindingType.SECURITY,
                    risk="Why it matters",
                    arn=resource.get('Arn', ''),
                ))
    except Exception:
        pass  # never raise — return empty list on failure

    return findings
```

### Step 3: Register the CLI command (optional)

Add to `kosty/cli/{service}_commands.py`:

```python
@myservice.command('check-something')
@common_options
@click.pass_context
def myservice_check_something(ctx, profile, ...):
    """Short description"""
    execute_engine_command(ctx, 'MyService', None, output, ..., check_id='aws-myservice-001')
```

### Rules

1. Always return `List[Finding]`, even if empty
2. Never raise exceptions — wrap in try/except, return `[]`
3. Use `session.client(service, region_name=region)` for boto3
4. Check ID format: `aws-{service}-{number:03d}`
5. One check per file (or closely related checks in one file)
6. The `compliance_ids` field is reserved for the Pro version

### Finding Fields Reference

| Field | Required | Description |
|-------|----------|-------------|
| `check_id` | ✅ | Must match the decorator |
| `service` | ✅ | Service display name |
| `resource_id` | ✅ | AWS resource identifier |
| `region` | ✅ | AWS region |
| `account_id` | ✅ | AWS account ID |
| `issue` | ✅ | Human-readable problem statement |
| `severity` | ✅ | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `finding_type` | ✅ | SECURITY or COST |
| `risk` | Optional | Why this matters (impact) |
| `arn` | Optional | Full ARN of the resource |
| `resource_name` | Optional | Friendly name (defaults to resource_id) |
| `details` | Optional | Dict of extra context (flattened in JSON output) |
| `monthly_savings` | Optional | For COST findings only |
| `compliance_ids` | Reserved | Pro version — maps to CIS/PCI/GDPR controls |

## Gating (OSS vs Premium)

The engine loads plugins from directories. No conditional logic in core.

```python
# OSS mode (default)
engine.load_plugins('providers/aws/services')

# Premium mode (Pro adds a second path)
engine.load_plugins('providers/aws/services')
engine.load_plugins('/opt/kosty-pro/plugins')
```

Premium plugins follow the exact same format. They just live in a private repo that's mounted/installed only in the Pro environment.

## Current State (v3.0.0)

- **151 native plugin checks** across 32 services in `kosty/providers/aws/services/`
- **CLI fully wired to engine** — `kosty audit`, all service commands, `kosty ai`, `kosty public-exposure`
- **Legacy files retained** in `kosty/services/` (dead code, kept for reference)
- **Zero legacy execution paths** — everything runs through the plugin registry

## Migration Path

| Stage | Status | What happened |
|-------|--------|---------------|
| Phase 1 | ✅ | Core engine, registry, loader, models, provider |
| Phase 2 | ✅ | All 151 checks migrated to native plugins |
| Phase 3 | ✅ | CLI `kosty audit` wired to EngineScanner |
| Phase 4 | ✅ | All individual service commands wired to engine |
| Phase 5 | Planned | Remove legacy `kosty/services/` files |
