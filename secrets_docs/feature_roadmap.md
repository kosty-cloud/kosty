# Kosty Feature Roadmap

## v2.0.0 — Completed

- `kosty ai` command (Bedrock 12 checks + SageMaker 8 checks)
- `kosty public-exposure` (15 resource types)
- IAM privilege escalation (21 patterns + --deep)
- WAFv2 service (6 checks)
- API Gateway hardening (10 checks)
- 13 foundational services (CloudTrail, VPC, GuardDuty, Config, SecretsManager, KMS, ACM, ElastiCache, SNS, SQS, ECS, SSM, Bedrock)
- RDS oversized false-positive fix (dynamic min instance detection)
- Report improvements (cost/security split, deduplicated findings)
- 31 services, 220+ checks total

## v3.0.0 — The Platform Engine

Goal: Transform Kosty from a CLI tool into an importable scan engine with plugin-based architecture. This enables SaaS integration, premium gating, and future multi-provider support without modifying core logic.

### Phase 1: Core Engine

| Task | File | Status |
|------|------|--------|
| CheckRegistry with @register_check decorator | `kosty/core/registry.py` | ✅ |
| PluginLoader (importlib, multi-path scan) | `kosty/core/loader.py` | ✅ |
| ScanEngine (importable, CLI-independent) | `kosty/core/engine.py` | ✅ |
| Standardized data models (CheckResult, Finding) | `kosty/core/models.py` | ✅ |
| Provider Interface (abstract base) | `kosty/core/provider.py` | ✅ |

### Phase 2: AWS Provider Layer

| Task | File | Status |
|------|------|--------|
| Centralized session/client factory | `providers/aws/__init__.py` | ✅ |
| Service Adapter (wraps legacy *_audit.py) | `providers/aws/adapter.py` | ✅ |
| Migrate 1-2 services as proof of concept | `providers/aws/services/cloudtrail/` | ✅ |

### Phase 3: CLI Integration

| Task | File | Status |
|------|------|--------|
| EngineScanner replaces ComprehensiveScanner | `kosty/core/engine_scanner.py` | ✅ |
| `kosty audit` uses engine path | `kosty/cli/__init__.py` | ✅ |
| `kosty --all` uses engine path | `kosty/cli/__init__.py` | ✅ |
| Backward-compatible (same commands, same output) | — | ✅ |
| Plugin search paths configurable | `kosty.yaml` | 🔲 |

### Phase 4: Progressive Service Migration

| Task | Status |
|------|--------|
| All 31 services migrated to native plugins | ✅ (150 checks) |
| CLI `kosty audit` wired to engine | ✅ |
| Full audit validated (190 issues, 31 services) | ✅ |
| Wire individual service commands to engine | 🔲 |
| Remove legacy `kosty/services/` files | 🔲 |

### Phase 5: Documentation

| Task | File | Status |
|------|------|--------|
| Architecture doc (Developer Guide) | `docs/ARCHITECTURE_V3.md` | ✅ |
| Plugin authoring guide | `docs/ARCHITECTURE_V3.md` | ✅ |
| README update | `README.md` | 🔲 |

### Design Decisions

**Gating (OSS vs Pro):**
- PluginLoader accepts multiple search paths
- OSS: scans `providers/aws/services/` only
- SaaS: scans `providers/aws/services/` + `plugins/pro/`
- No conditional logic in core — just additional paths

**Backward Compatibility:**
- Service Adapter wraps existing *_audit.py files
- CLI commands unchanged
- Output format unchanged
- Migration is invisible to end users

**Performance:**
- Lazy imports — plugins loaded on first scan, not at CLI startup
- Plugin failures isolated — one broken plugin doesn't crash the scan
- Centralized boto3 session avoids redundant STS calls

### Remaining from v2.x (Carried Over)

| Feature | Priority | Notes |
|---------|----------|-------|
| `--per-account` reporting | Low | One JSON/CSV per account in org mode |
| `kosty-compliance` (CIS/GDPR/PCI) | Future | Separate product, uses engine as library |
| Exceptions CSV (silence findings) | Medium | Integrates with report layer |
