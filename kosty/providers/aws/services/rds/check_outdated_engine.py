from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags


@register_check(check_id="aws-rds-013", service="RDS", provider="aws", finding_type=FindingType.SECURITY, description="Find outdated engine versions")
def check_outdated_engine(session, region, **kwargs):
    """Flag databases on EOL engine versions."""
    rds = session.client('rds', region_name=region)
    account_id = get_account_id(session)
    findings = []
    old_versions = {'mysql': ['5.6', '5.7.0'], 'postgres': ['9.', '10.', '11.0'], 'oracle': ['11.', '12.1']}
    try:
        for db in rds.describe_db_instances()['DBInstances']:
            if excluded_by_tags(db, kwargs):
                continue
            engine = db.get('Engine', '').lower()
            version = db.get('EngineVersion', '')
            for eng, prefixes in old_versions.items():
                if eng in engine and any(version.startswith(p) for p in prefixes):
                    findings.append(Finding(
                        check_id="aws-rds-013", service="RDS",
                        resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                        issue=f"Outdated: {engine} {version}", severity=Severity.MEDIUM,
                        finding_type=FindingType.SECURITY, risk="Known CVEs unpatched", arn=db['DBInstanceArn'],
                    ))
                    break
    except Exception:
        pass
    return findings
