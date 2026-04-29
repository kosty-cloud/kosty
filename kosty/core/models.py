"""Standardized data models for the Kosty scan engine.

These dataclasses define the contract between plugins and the core.
All checks must return Finding instances. The engine aggregates them
into ScanResult containers.

The Finding model is designed to be consumed by:
- The CLI reporter (console/JSON/CSV output)
- The web dashboard (JSON upload)
- The future kosty-compliance module (CIS/PCI/GDPR mapping)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    COST = "cost"
    SECURITY = "security"


@dataclass
class Finding:
    """A single audit finding produced by a check.

    Required fields: check_id, service, resource_id, region, account_id,
                     issue, severity, finding_type

    Compliance-ready: compliance_ids maps framework → control IDs.
    Example: {"CIS": ["1.4", "1.5"], "PCI": ["8.3.1"]}
    """

    check_id: str
    service: str
    resource_id: str
    region: str
    account_id: str
    issue: str
    severity: Severity
    finding_type: FindingType
    risk: str = ""
    resource_name: str = ""
    arn: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    monthly_savings: float = 0.0
    compliance_ids: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to the standard output format.

        Produces a flat dict compatible with:
        - Legacy dashboard (Service, Issue, severity, type, Region, ResourceId)
        - CLI reporter
        - Future compliance module (check_id, compliance_ids)
        """
        d = {
            'AccountId': self.account_id,
            'Region': self.region,
            'region': self.region,
            'Service': self.service,
            'service': self.service,
            'ResourceId': self.resource_id,
            'resource_id': self.resource_id,
            'ResourceName': self.resource_name or self.resource_id,
            'resource_name': self.resource_name or self.resource_id,
            'ARN': self.arn,
            'Issue': self.issue,
            'type': self.finding_type.value,
            'severity': self.severity.value,
            'Risk': self.risk,
            'check': self.check_id,
            'monthly_savings': self.monthly_savings,
        }
        # Flatten details to root level for backward compat
        if self.details:
            d.update(self.details)
        # Include compliance mapping if present
        if self.compliance_ids:
            d['compliance_ids'] = self.compliance_ids
        return d


@dataclass
class CheckMetadata:
    """Metadata describing a registered check."""

    check_id: str
    service: str
    provider: str
    finding_type: FindingType
    description: str = ""
    requires_deep: bool = False
    compliance_ids: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Aggregated results from a scan run."""

    timestamp: datetime = field(default_factory=datetime.utcnow)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def total_issues(self) -> int:
        return len(self.findings)

    @property
    def total_savings(self) -> float:
        return sum(f.monthly_savings for f in self.findings)

    @property
    def security_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.finding_type == FindingType.SECURITY]

    @property
    def cost_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.finding_type == FindingType.COST]

    def findings_by_service(self) -> Dict[str, List[Finding]]:
        grouped: Dict[str, List[Finding]] = {}
        for f in self.findings:
            grouped.setdefault(f.service, []).append(f)
        return grouped

    def findings_by_compliance(self, framework: str) -> Dict[str, List[Finding]]:
        """Group findings by compliance control ID for a given framework.

        Args:
            framework: Compliance framework name (e.g., "CIS", "PCI").

        Returns:
            Dict mapping control_id to list of findings.
        """
        grouped: Dict[str, List[Finding]] = {}
        for f in self.findings:
            for control_id in f.compliance_ids.get(framework, []):
                grouped.setdefault(control_id, []).append(f)
        return grouped

    def to_dict(self) -> Dict[str, Any]:
        return {
            'scan_timestamp': self.timestamp.isoformat(),
            'total_issues': self.total_issues,
            'total_monthly_savings': self.total_savings,
            'findings': [f.to_dict() for f in self.findings],
            'errors': self.errors,
        }
