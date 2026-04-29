# Kosty v3.0.0 — Plugin Architecture

## Overview

Kosty v3 introduces a plugin-based scan engine. The core is now an importable library that discovers, loads, and executes checks from any directory. This decouples the scan logic from the CLI and enables:

- **SaaS integration** — import the engine, inject a session, get JSON results
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
│  aws-iam-001 ... aws-iam-018 (via adapter)          │
│  aws-s3-001 ... aws-s3-013 (via adapter)            │
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

### File Structure

```
providers/aws/services/my_service/
├── __init__.py          # empty
└── checks.py            # check functions with @register_check
```

### Check Function Contract

```python
@register_check(
    check_id="aws-myservice-001",      # unique, prefixed by provider
    service="MyService",                # display name
    provider="aws",                     # provider filter
    finding_type=FindingType.SECURITY,  # SECURITY or COST
    description="What this check does",
)
def check_something(session, region, **kwargs):
    """One-line docstring explaining the check."""
    # session = boto3.Session (or equivalent)
    # region = target region string
    # kwargs may contain: deep, config_manager, days, etc.
    
    findings = []
    # ... your logic ...
    findings.append(Finding(...))
    return findings  # always return a list
```

### Rules

1. Always return `List[Finding]`, even if empty
2. Never raise exceptions — catch and return empty list
3. Use `session.client(service, region_name=region)` for boto3 calls
4. Check ID format: `{provider}-{service}-{number:03d}`
5. One check per logical concern (don't bundle unrelated checks)

## Gating (OSS vs Premium)

The engine loads plugins from directories. No conditional logic in core.

```python
# OSS mode (default)
engine.load_plugins('providers/aws/services')

# Premium mode (SaaS adds a second path)
engine.load_plugins('providers/aws/services')
engine.load_plugins('/opt/kosty-pro/plugins')
```

Premium plugins follow the exact same format. They just live in a private repo that's mounted/installed only in the SaaS environment.

## Migration Path

| Stage | What happens |
|-------|-------------|
| Current | Legacy services work via adapter. Native plugins coexist. |
| Next | Migrate services one at a time to `providers/aws/services/` |
| Final | Remove adapter. All checks are native plugins. |

The adapter ensures zero downtime during migration. Both paths produce identical results.
