"""Standardized data models for the Kosty scan engine.

These dataclasses define the contract between plugins and the core.
All checks must return Finding instances. The engine aggregates them
into ScanResult containers.
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
    """A single audit finding produced by a check."""

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

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to the legacy issue dictionary format for backward compat."""
        return {
            'AccountId': self.account_id,
            'Region': self.region,
            'Service': self.service,
            'ResourceId': self.resource_id,
            'ResourceName': self.resource_name or self.resource_id,
            'ARN': self.arn,
            'Issue': self.issue,
            'type': self.finding_type.value,
            'severity': self.severity.value,
            'Risk': self.risk,
            'check': self.check_id,
            'Details': self.details,
            'monthly_savings': self.monthly_savings,
        }


@dataclass
class CheckMetadata:
    """Metadata describing a registered check."""

    check_id: str
    service: str
    provider: str
    finding_type: FindingType
    description: str = ""
    requires_deep: bool = False


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

    def to_dict(self) -> Dict[str, Any]:
        return {
            'scan_timestamp': self.timestamp.isoformat(),
            'total_issues': self.total_issues,
            'total_monthly_savings': self.total_savings,
            'findings': [f.to_dict() for f in self.findings],
            'errors': self.errors,
        }
