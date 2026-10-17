#!/usr/bin/env python3
"""Generate the two demo JSON reports consumed by the web dashboard.

This script is fully offline: it makes no AWS calls, imports no boto3, and does
not import the kosty package. It builds in-memory finding dicts that match the
exact shape produced by ``kosty.core.models.Finding.to_dict`` and wraps them in
the same envelope as ``kosty.core.reporter.CostOptimizationReporter.save_json_report``.

Keeping the serialization logic self-contained lets the demos match real audit
output by construction while staying runnable in environments without network,
AWS credentials, or the heavy runtime dependencies.

Output (both anonymized by construction — demo account 123456789012, generic
resource names, fixed fake ARN suffixes, fixed neutral timestamp):
    dashboard/demo_full_audit.json  — mixed cost + security scan, many services
    dashboard/demo_ai_audit.json    — AI-focused scan (Bedrock / SageMaker)

Usage:
    python scripts/generate_demo_dashboard.py
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

# Fixed, neutral values so regenerated demos are deterministic and anonymized.
DEMO_ACCOUNT = "123456789012"
DEMO_REGION = "us-east-1"
SCAN_TIMESTAMP = "2025-01-15T10:00:00+00:00"

DASHBOARD_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard"
)


def finding(
    *,
    check_id: str,
    service: str,
    resource_id: str,
    issue: str,
    severity: str,
    finding_type: str,
    risk: str = "",
    resource_name: str = "",
    arn: str = "",
    monthly_savings: float = 0.0,
    region: str = DEMO_REGION,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build one finding dict identical to ``Finding.to_dict()`` output.

    Mirrors kosty/core/models.py: both casings for compat, ``type``/``severity``
    lowercase, ``check`` carries the check_id, cost findings carry monthly_savings.
    Global-scope checks (S3, IAM) pass region="global".
    """
    name = resource_name or resource_id
    item: Dict[str, Any] = {
        "AccountId": DEMO_ACCOUNT,
        "Region": region,
        "region": region,
        "Service": service,
        "service": service,
        "ResourceId": resource_id,
        "resource_id": resource_id,
        "ResourceName": name,
        "resource_name": name,
        "ARN": arn,
        "Issue": issue,
        "type": finding_type,
        "severity": severity,
        "Risk": risk,
        "check": check_id,
        "monthly_savings": monthly_savings,
    }
    if details:
        item.update(details)
    return item


def build_report(
    findings: List[Dict[str, Any]], extra_top_level: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Wrap a flat finding list in the save_json_report envelope.

    Matches kosty/core/reporter.py: ``results.<account>`` is a flat array and the
    ``summary`` key is always present.
    """
    total = len(findings)
    report: Dict[str, Any] = {
        "scan_timestamp": SCAN_TIMESTAMP,
        "total_issues": total,
    }
    if extra_top_level:
        report.update(extra_top_level)
    report["results"] = {DEMO_ACCOUNT: findings}
    report["summary"] = {"total_accounts": 1, "total_issues": total}
    return report


def demo_full_findings() -> List[Dict[str, Any]]:
    """A rich mixed scan across many services and both finding types.

    Every cost finding carries a coherent monthly_savings. Resource names are
    generic demo placeholders, ARNs use fixed fake suffixes.
    """
    f: List[Dict[str, Any]] = []

    # --- EC2 ---
    f.append(finding(
        check_id="aws-ec2-003", service="EC2", resource_id="i-0demoaaaa1111aaaa",
        resource_name="demo-web-01", finding_type="cost", severity="high",
        monthly_savings=182.40,
        issue="Oversized instance (m5.2xlarge) averaging 6% CPU over 14 days",
        risk="Paying for compute that is never used — rightsize to m5.large",
    ))
    f.append(finding(
        check_id="aws-ec2-003", service="EC2", resource_id="i-0demoaaaa2222aaaa",
        resource_name="demo-worker-02", finding_type="cost", severity="medium",
        monthly_savings=74.00,
        issue="Oversized instance (c5.xlarge) averaging 11% CPU over 14 days",
        risk="Consistent underutilization — a smaller type would serve the load",
    ))
    f.append(finding(
        check_id="aws-ec2-004", service="EC2", resource_id="i-0demoaaaa3333aaaa",
        resource_name="demo-legacy-01", finding_type="cost", severity="low",
        monthly_savings=23.50,
        issue="Previous generation instance type (m4.large)",
        risk="Current generation is 10-20% cheaper for the same performance",
    ))
    f.append(finding(
        check_id="aws-ec2-005", service="EC2", resource_id="i-0demoaaaa4444aaaa",
        resource_name="demo-bastion-01", finding_type="security", severity="high",
        issue="SSH (port 22) open to 0.0.0.0/0",
        risk="Any host on the internet can attempt to log in",
    ))
    f.append(finding(
        check_id="aws-ec2-007", service="EC2", resource_id="i-0demoaaaa5555aaaa",
        resource_name="demo-db-host-01", finding_type="security", severity="critical",
        issue="Database port (3306) open to 0.0.0.0/0",
        risk="Database reachable from the entire internet",
    ))

    # --- EBS ---
    f.append(finding(
        check_id="aws-ebs-001", service="EBS", resource_id="vol-0demobbbb1111bbbb",
        resource_name="demo-orphan-vol-a", finding_type="cost", severity="medium",
        monthly_savings=40.00,
        issue="Detached volume (400 GB gp3) in available state",
        risk="Billed storage attached to nothing",
    ))
    f.append(finding(
        check_id="aws-ebs-007", service="EBS", resource_id="vol-0demobbbb2222bbbb",
        resource_name="demo-lowio-vol-b", finding_type="cost", severity="low",
        monthly_savings=16.00,
        issue="In-use volume with near-zero I/O over 7 days",
        risk="Likely oversized — a smaller or cheaper volume type would suffice",
    ))
    f.append(finding(
        check_id="aws-ebs-003", service="EBS", resource_id="vol-0demobbbb3333bbbb",
        resource_name="demo-orphan-vol-c", finding_type="security", severity="medium",
        issue="Unencrypted detached volume",
        risk="Data at rest without encryption and no owner",
    ))

    # --- S3 ---
    f.append(finding(
        check_id="aws-s3-004", service="S3", resource_id="demo-public-assets",
        resource_name="demo-public-assets", finding_type="security", severity="high",
        region="global",
        arn="arn:aws:s3:::demo-public-assets",
        issue="Bucket grants public read via ACL (AllUsers)",
        risk="Anyone can list and download objects",
    ))
    f.append(finding(
        check_id="aws-s3-008", service="S3", resource_id="demo-data-lake",
        resource_name="demo-data-lake", finding_type="security", severity="low",
        arn="arn:aws:s3:::demo-data-lake",
        issue="Bucket has no access logging configured",
        risk="No audit trail of who accessed what",
    ))

    # --- RDS ---
    f.append(finding(
        check_id="aws-rds-001", service="RDS", resource_id="demo-db-cluster",
        resource_name="demo-db-cluster", finding_type="cost", severity="high",
        monthly_savings=240.00,
        issue="Oversized instance (db.r5.2xlarge) averaging 8% CPU",
        risk="Right-size to db.r5.large for the observed load",
    ))
    f.append(finding(
        check_id="aws-rds-004", service="RDS", resource_id="demo-db-public",
        resource_name="demo-db-public", finding_type="security", severity="critical",
        issue="RDS instance is publicly accessible",
        risk="Database endpoint resolvable and reachable from the internet",
    ))

    # --- IAM ---
    f.append(finding(
        check_id="aws-iam-005", service="IAM", resource_id="demo-ci-user",
        resource_name="demo-ci-user", finding_type="security", severity="medium",
        region="global",
        arn="arn:aws:iam::123456789012:user/demo-ci-user",
        issue="Access key older than 90 days (never rotated)",
        risk="Stale long-lived credential increases exposure window",
    ))
    f.append(finding(
        check_id="aws-iam-009", service="IAM", resource_id="demo-admin-policy",
        resource_name="demo-admin-policy", finding_type="security", severity="high",
        region="global",
        arn="arn:aws:iam::123456789012:policy/demo-admin-policy",
        issue="Customer-managed policy grants Action:* on Resource:*",
        risk="God-mode permissions — violates least privilege",
    ))
    f.append(finding(
        check_id="aws-iam-006", service="IAM", resource_id="demo-old-user",
        resource_name="demo-old-user", finding_type="security", severity="medium",
        region="global",
        arn="arn:aws:iam::123456789012:user/demo-old-user",
        issue="Active access key unused for 90+ days",
        risk="Dormant credential with no business value is pure attack surface",
    ))

    # --- SG ---
    f.append(finding(
        check_id="aws-sg-001", service="SG", resource_id="sg-0democcc1111",
        resource_name="demo-admin-sg", finding_type="security", severity="high",
        issue="Security group allows SSH/RDP from 0.0.0.0/0",
        risk="Admin ports reachable from the whole internet",
    ))
    f.append(finding(
        check_id="aws-sg-003", service="SG", resource_id="sg-0democcc2222",
        resource_name="demo-unused-sg", finding_type="cost", severity="low",
        monthly_savings=0.0,
        issue="Security group not attached to any resource",
        risk="Orphaned configuration adds clutter and audit noise",
        details={"note": "no direct charge; housekeeping finding"},
    ))

    # --- Load Balancer ---
    f.append(finding(
        check_id="aws-lb-001", service="LB", resource_id="demo-idle-alb",
        resource_name="demo-idle-alb", finding_type="cost", severity="medium",
        monthly_savings=22.50,
        issue="Load balancer with no healthy targets for 30 days",
        risk="Paying hourly for a balancer that serves no traffic",
    ))

    # --- CloudWatch ---
    f.append(finding(
        check_id="aws-cloudwatch-001", service="CloudWatch",
        resource_id="/demo/app/logs", resource_name="/demo/app/logs",
        finding_type="cost", severity="low", monthly_savings=12.80,
        issue="Log group with no retention policy (never expires)",
        risk="Logs accumulate and bill indefinitely",
    ))

    # --- Bedrock ---
    f.append(finding(
        check_id="aws-bedrock-003", service="Bedrock", resource_id="bedrock-guardrails",
        resource_name="Bedrock Guardrails", finding_type="security", severity="high",
        issue="No Bedrock Guardrails configured",
        risk="No protection against prompt injection, PII leakage, or toxic content",
    ))
    f.append(finding(
        check_id="aws-bedrock-002", service="Bedrock", resource_id="bedrock-budget",
        resource_name="Bedrock Budget", finding_type="cost", severity="high",
        monthly_savings=150.00,
        issue="No AWS Budget configured for Bedrock spend",
        risk="Runaway GenAI usage can bill without any alert",
    ))

    # --- SageMaker ---
    f.append(finding(
        check_id="aws-sagemaker-001", service="SageMaker", resource_id="demo-sm-endpoint",
        resource_name="demo-sm-endpoint", finding_type="cost", severity="high",
        monthly_savings=1036.80,
        issue="Idle GPU endpoint (ml.g5.xlarge) with 0 invocations in 7 days",
        risk="A GPU endpoint billed 24/7 while serving no traffic",
    ))

    return f


def demo_ai_findings() -> List[Dict[str, Any]]:
    """An AI-focused scan (Bedrock / SageMaker), both finding types.

    Uses real check_ids and carries monthly_savings on every cost finding.
    """
    f: List[Dict[str, Any]] = []

    f.append(finding(
        check_id="aws-bedrock-002", service="Bedrock", resource_id="bedrock-budget",
        resource_name="Bedrock Budget", finding_type="cost", severity="high",
        monthly_savings=150.00,
        issue="No AWS Budget configured for Bedrock spend",
        risk="A stolen API key or runaway automation means unlimited GenAI spend with no alert",
    ))
    f.append(finding(
        check_id="aws-bedrock-007", service="Bedrock", resource_id="prompt-caching",
        resource_name="Prompt Caching", finding_type="cost", severity="medium",
        monthly_savings=320.00,
        issue="Cache-compatible models available — verify prompt caching is enabled in your app",
        risk="Up to 90% savings on repeated system prompts and RAG contexts if caching is enabled",
    ))
    f.append(finding(
        check_id="aws-bedrock-008", service="Bedrock", resource_id="inference-profiles",
        resource_name="Application Inference Profiles", finding_type="cost",
        severity="low", monthly_savings=0.0,
        issue="No Application Inference Profiles configured",
        risk="No per-team cost attribution for GenAI spend",
        details={"note": "enables cost attribution; no direct charge"},
    ))
    f.append(finding(
        check_id="aws-bedrock-001", service="Bedrock", resource_id="bedrock-logging",
        resource_name="Bedrock Logging", finding_type="security", severity="high",
        issue="Bedrock model invocation logging not enabled",
        risk="No audit trail on GenAI usage — prompt injection and data leakage go undetected",
    ))
    f.append(finding(
        check_id="aws-bedrock-003", service="Bedrock", resource_id="bedrock-guardrails",
        resource_name="Bedrock Guardrails", finding_type="security", severity="high",
        issue="No Bedrock Guardrails configured",
        risk="No protection against prompt injection, PII leakage, or toxic content in model responses",
    ))
    f.append(finding(
        check_id="aws-bedrock-004", service="Bedrock", resource_id="demo-scanner-role",
        resource_name="demo-scanner-role", finding_type="security", severity="medium",
        arn="arn:aws:iam::123456789012:role/demo-scanner-role",
        issue="IAM role with AI/ML permissions not tagged as approved project",
        risk="Potential shadow AI usage — untracked GenAI spend and data exposure",
    ))
    f.append(finding(
        check_id="aws-bedrock-005", service="Bedrock", resource_id="bedrock-vpc-endpoint",
        resource_name="Bedrock VPC Endpoint", finding_type="security", severity="medium",
        issue="No VPC Interface Endpoint for Bedrock runtime",
        risk="Model invocations traverse the public internet instead of staying within the VPC",
    ))
    f.append(finding(
        check_id="aws-sagemaker-001", service="SageMaker", resource_id="demo-sm-endpoint",
        resource_name="demo-sm-endpoint", finding_type="cost", severity="high",
        monthly_savings=1036.80,
        issue="Idle GPU endpoint (ml.g5.xlarge) with 0 invocations in 7 days",
        risk="A GPU endpoint billed around the clock while serving no traffic",
    ))
    f.append(finding(
        check_id="aws-sagemaker-005", service="SageMaker",
        resource_id="sagemaker-vpc-endpoint", resource_name="SageMaker VPC Endpoint",
        finding_type="security", severity="medium",
        issue="No VPC Interface Endpoint for SageMaker API",
        risk="SageMaker API calls traverse the public internet",
    ))

    return f


def write_json(path: str, data: Dict[str, Any]) -> None:
    """Write pretty-printed JSON matching the reporter's formatting."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def main() -> None:
    full = build_report(demo_full_findings())
    ai = build_report(demo_ai_findings(), extra_top_level={"method": "ai_audit"})

    full_path = os.path.join(DASHBOARD_DIR, "demo_full_audit.json")
    ai_path = os.path.join(DASHBOARD_DIR, "demo_ai_audit.json")

    write_json(full_path, full)
    write_json(ai_path, ai)

    print(f"wrote {full_path} ({full['total_issues']} findings)")
    print(f"wrote {ai_path} ({ai['total_issues']} findings)")


if __name__ == "__main__":
    main()
