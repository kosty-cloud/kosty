"""Offline tests for config honoring in the v3 scan path.

Covers the capabilities restored in 3.2.0:
  (a) exclude.regions filtering,
  (b) kosty.yaml thresholds driving the checks (CLI > config > default),
  (c) threshold key agreement across config, example, and docs.

Everything here is offline: no boto3/STS. Sessions are MagicMocks and
account resolution is stubbed, so no network call is ever made.
"""

import re
import textwrap
from unittest.mock import MagicMock

import pytest

from kosty.core.config import ConfigManager, DEFAULT_THRESHOLDS, resolve_threshold


REPO_ROOT = __import__('pathlib').Path(__file__).resolve().parents[1]


def _write_config(tmp_path, body: str) -> ConfigManager:
    """Write a kosty.yaml in tmp_path and return a ConfigManager for it."""
    config_file = tmp_path / "kosty.yaml"
    config_file.write_text(textwrap.dedent(body))
    return ConfigManager(config_file=str(config_file))


def _fake_session(account_id: str = "123456789012") -> MagicMock:
    """Build a MagicMock boto3 session with STS identity stubbed."""
    session = MagicMock()
    session.client.return_value.get_caller_identity.return_value = {'Account': account_id}
    return session


# ---------------------------------------------------------------------------
# (a) exclude.regions
# ---------------------------------------------------------------------------

def test_should_exclude_region_predicate(tmp_path):
    """The predicate reports excluded regions and keeps the rest."""
    cm = _write_config(tmp_path, """
        exclude:
          regions:
            - eu-west-3
    """)
    assert cm.should_exclude_region("eu-west-3") is True
    assert cm.should_exclude_region("us-east-1") is False


def test_engine_scanner_filters_excluded_region(tmp_path):
    """EngineScanner drops excluded regions from its resolved region list."""
    from kosty.core.engine_scanner import EngineScanner

    cm = _write_config(tmp_path, """
        exclude:
          regions:
            - eu-west-3
    """)
    scanner = EngineScanner(
        organization=False,
        regions=["us-east-1", "eu-west-3"],
        max_workers=2,
        config_manager=cm,
        session=_fake_session(),
    )
    assert scanner.regions == ["us-east-1"]


def test_engine_scanner_keeps_regions_without_exclusion(tmp_path):
    """With no region exclusion, the full region list is kept."""
    from kosty.core.engine_scanner import EngineScanner

    cm = _write_config(tmp_path, """
        default:
          max_workers: 2
    """)
    scanner = EngineScanner(
        organization=False,
        regions=["us-east-1", "eu-west-3"],
        max_workers=2,
        config_manager=cm,
        session=_fake_session(),
    )
    assert scanner.regions == ["us-east-1", "eu-west-3"]


# ---------------------------------------------------------------------------
# (b) thresholds drive the checks — CLI > config > default
# ---------------------------------------------------------------------------

def test_resolve_threshold_precedence(tmp_path):
    """resolve_threshold honors CLI kwarg over config over default."""
    cm = _write_config(tmp_path, """
        thresholds:
          ec2_cpu: 35
    """)
    # CLI kwarg wins over config
    assert resolve_threshold({'cpu_threshold': 10, 'config_manager': cm}, 'cpu_threshold', 'ec2_cpu', 20) == 10
    # Config wins over hardcoded default when no CLI kwarg
    assert resolve_threshold({'config_manager': cm}, 'cpu_threshold', 'ec2_cpu', 20) == 35
    # Default when neither CLI kwarg nor config value present
    assert resolve_threshold({}, 'cpu_threshold', 'nonexistent_key', 20) == 20


def _ec2_oversized_session(cpu_avg: float):
    """Session returning one running instance at the given average CPU."""
    session = _fake_session()
    ec2 = MagicMock()
    ec2.describe_instances.return_value = {
        'Reservations': [{'Instances': [{
            'InstanceId': 'i-abc', 'InstanceType': 'm5.large', 'Tags': [],
        }]}]
    }
    cw = MagicMock()
    cw.get_metric_statistics.return_value = {'Datapoints': [{'Average': cpu_avg}]}

    def client(name, **kwargs):
        if name == 'ec2':
            return ec2
        if name == 'cloudwatch':
            return cw
        sts = MagicMock()
        sts.get_caller_identity.return_value = {'Account': '123456789012'}
        return sts

    session.client.side_effect = client
    return session


def test_ec2_oversized_reads_cpu_threshold_from_config(tmp_path):
    """ec2 oversized flags based on the config ec2_cpu value."""
    from kosty.providers.aws.services.ec2.check_oversized_instances import check_oversized_instances

    # Instance at 25% CPU. Default threshold is 20 → not flagged.
    (tmp_path / "a").mkdir(exist_ok=True)
    cm_default = _write_config(tmp_path / "a", "default: {}")
    session = _ec2_oversized_session(25.0)
    findings = check_oversized_instances(session, 'us-east-1', config_manager=cm_default)
    assert findings == []

    # Config raises threshold to 30 → 25% now counts as oversized.
    (tmp_path / "b").mkdir(exist_ok=True)
    cm_strict = _write_config(tmp_path / "b", """
        thresholds:
          ec2_cpu: 30
    """)
    session = _ec2_oversized_session(25.0)
    findings = check_oversized_instances(session, 'us-east-1', config_manager=cm_strict)
    assert len(findings) == 1


def test_ec2_oversized_cli_flag_wins_over_config(tmp_path):
    """An explicit cpu_threshold kwarg overrides the config value."""
    from kosty.providers.aws.services.ec2.check_oversized_instances import check_oversized_instances

    cm = _write_config(tmp_path, """
        thresholds:
          ec2_cpu: 30
    """)
    # Config would flag 25% (<30), but CLI flag of 20 should not.
    session = _ec2_oversized_session(25.0)
    findings = check_oversized_instances(session, 'us-east-1', config_manager=cm, cpu_threshold=20)
    assert findings == []


def _ec2_stopped_session(days_ago: int):
    """Session returning one instance stopped days_ago days back."""
    from datetime import datetime, timedelta
    session = _fake_session()
    stopped_at = (datetime.now() - timedelta(days=days_ago)).strftime('%Y-%m-%d %H:%M:%S GMT')
    ec2 = MagicMock()
    ec2.describe_instances.return_value = {
        'Reservations': [{'Instances': [{
            'InstanceId': 'i-stopped', 'InstanceType': 'm5.large', 'Tags': [],
            'StateTransitionReason': f'User initiated ({stopped_at})',
        }]}]
    }

    def client(name, **kwargs):
        if name == 'ec2':
            return ec2
        sts = MagicMock()
        sts.get_caller_identity.return_value = {'Account': '123456789012'}
        return sts

    session.client.side_effect = client
    return session


def test_ec2_stopped_reads_stopped_days_from_config(tmp_path):
    """ec2 stopped flags based on the config stopped_days value."""
    from kosty.providers.aws.services.ec2.check_stopped_instances import check_stopped_instances

    # Instance stopped 5 days ago. Default stopped_days=7 → not flagged.
    (tmp_path / "d").mkdir(exist_ok=True)
    cm_default = _write_config(tmp_path / "d", "default: {}")
    session = _ec2_stopped_session(5)
    assert check_stopped_instances(session, 'us-east-1', config_manager=cm_default) == []

    # Config lowers stopped_days to 3 → 5-day-old stop now flagged.
    (tmp_path / "e").mkdir(exist_ok=True)
    cm_strict = _write_config(tmp_path / "e", """
        thresholds:
          stopped_days: 3
    """)
    session = _ec2_stopped_session(5)
    assert len(check_stopped_instances(session, 'us-east-1', config_manager=cm_strict)) == 1


def _snapshots_session(age_days: int):
    """Session returning one snapshot age_days old."""
    from datetime import datetime, timedelta
    session = _fake_session()
    ec2 = MagicMock()
    ec2.describe_snapshots.return_value = {
        'Snapshots': [{
            'SnapshotId': 'snap-1', 'VolumeSize': 100, 'Tags': [],
            'StartTime': datetime.now() - timedelta(days=age_days),
        }]
    }

    def client(name, **kwargs):
        if name == 'ec2':
            return ec2
        sts = MagicMock()
        sts.get_caller_identity.return_value = {'Account': '123456789012'}
        return sts

    session.client.side_effect = client
    return session


def test_snapshots_default_and_config_and_cli(tmp_path):
    """old_snapshot_days: default 30, config override, and CLI override."""
    from kosty.providers.aws.services.snapshots_svc.check_old_snapshots import check_old_snapshots

    # 45-day-old snapshot. Default old_snapshot_days=30 → flagged.
    (tmp_path / "s1").mkdir(exist_ok=True)
    cm_default = _write_config(tmp_path / "s1", "default: {}")
    session = _snapshots_session(45)
    assert len(check_old_snapshots(session, 'us-east-1', config_manager=cm_default)) == 1

    # Config raises old_snapshot_days to 60 → 45-day snapshot not flagged.
    (tmp_path / "s2").mkdir(exist_ok=True)
    cm_lenient = _write_config(tmp_path / "s2", """
        thresholds:
          old_snapshot_days: 60
    """)
    session = _snapshots_session(45)
    assert check_old_snapshots(session, 'us-east-1', config_manager=cm_lenient) == []

    # CLI days=60 wins even though config/default would flag it.
    session = _snapshots_session(45)
    assert check_old_snapshots(session, 'us-east-1', config_manager=cm_default, days=60) == []


def test_snapshot_legacy_key_fallback(tmp_path):
    """Legacy snapshot_days is read as a fallback for old_snapshot_days."""
    cm = _write_config(tmp_path, """
        thresholds:
          snapshot_days: 60
    """)
    assert cm.get_threshold('old_snapshot_days') == 60


# ---------------------------------------------------------------------------
# (c) threshold key agreement across config, example, and docs
# ---------------------------------------------------------------------------

CANONICAL_KEYS = {
    'ec2_cpu', 'rds_cpu', 'lambda_memory',
    'stopped_days', 'idle_days', 'old_snapshot_days', 'ami_days',
}


def test_default_thresholds_match_canonical():
    """DEFAULT_THRESHOLDS keys equal the canonical set."""
    assert set(DEFAULT_THRESHOLDS.keys()) == CANONICAL_KEYS


def test_example_file_threshold_keys_match_canonical():
    """kosty.yaml.example top-level thresholds equal the canonical set."""
    import yaml
    data = yaml.safe_load((REPO_ROOT / "kosty.yaml.example").read_text())
    assert set(data['thresholds'].keys()) == CANONICAL_KEYS


def test_docs_threshold_table_matches_canonical():
    """The CONFIGURATION.md Available Thresholds table equals the canonical set."""
    text = (REPO_ROOT / "docs" / "CONFIGURATION.md").read_text()
    section = text.split("### Available Thresholds", 1)[1].split("##", 1)[0]
    keys = set(re.findall(r"^\|\s*`([a-z0-9_]+)`\s*\|", section, flags=re.MULTILINE))
    assert keys == CANONICAL_KEYS
