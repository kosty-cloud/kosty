"""Offline tests for config exclusions, timeout config, and save-to confinement.

No boto3/STS/network: ConfigManager is built from a kosty.yaml written under
tmp_path; build_boto_config only constructs a botocore Config object (no client,
no network); confine_local_path operates purely on paths.
"""

import textwrap

import pytest

from kosty.core.config import (
    ConfigManager,
    build_boto_config,
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    DEFAULT_MAX_RETRIES,
)
from kosty.core.exceptions import SaveLocationError
from kosty.core.storage import confine_local_path


def _write_config(tmp_path, body: str) -> ConfigManager:
    config_file = tmp_path / "kosty.yaml"
    config_file.write_text(textwrap.dedent(body))
    return ConfigManager(config_file=str(config_file))


# ---------------------------------------------------------------------------
# ARN exclusion (fnmatch)
# ---------------------------------------------------------------------------

def test_should_exclude_arn_wildcard_match(tmp_path):
    """An fnmatch pattern with wildcards matches the resource ARN."""
    cm = _write_config(tmp_path, """
        exclude:
          arns:
            - "arn:aws:ec2:us-east-1:*:instance/i-*"
    """)
    assert cm.should_exclude_arn("arn:aws:ec2:us-east-1:123456789012:instance/i-abc") is True
    assert cm.should_exclude_arn("arn:aws:ec2:eu-west-3:123456789012:instance/i-abc") is False


def test_should_exclude_arn_no_patterns(tmp_path):
    """With no ARN exclusions, nothing matches."""
    cm = _write_config(tmp_path, "default: {}")
    assert cm.should_exclude_arn("arn:aws:s3:::my-bucket") is False


# ---------------------------------------------------------------------------
# Tag exclusion — Key/Value and key/value casings
# ---------------------------------------------------------------------------

def test_should_exclude_by_tags_uppercase_casing(tmp_path):
    """AWS SDK 'Key'/'Value' casing is matched."""
    cm = _write_config(tmp_path, """
        exclude:
          tags:
            - key: env
              value: prod
    """)
    assert cm.should_exclude_by_tags([{'Key': 'env', 'Value': 'prod'}]) is True
    assert cm.should_exclude_by_tags([{'Key': 'env', 'Value': 'dev'}]) is False


def test_should_exclude_by_tags_lowercase_casing(tmp_path):
    """Lowercase 'key'/'value' casing is matched too."""
    cm = _write_config(tmp_path, """
        exclude:
          tags:
            - key: env
              value: prod
    """)
    assert cm.should_exclude_by_tags([{'key': 'env', 'value': 'prod'}]) is True


def test_should_exclude_by_tags_key_only_rule(tmp_path):
    """A rule with no value matches any tag carrying that key."""
    cm = _write_config(tmp_path, """
        exclude:
          tags:
            - key: temporary
    """)
    assert cm.should_exclude_by_tags([{'Key': 'temporary', 'Value': 'whatever'}]) is True
    assert cm.should_exclude_by_tags([{'Key': 'other', 'Value': 'x'}]) is False


# ---------------------------------------------------------------------------
# timeout config keys + build_boto_config
# ---------------------------------------------------------------------------

def test_timeout_defaults_present():
    """DEFAULT_CONFIG exposes the timeout keys with the historical defaults."""
    from kosty.core.config import DEFAULT_CONFIG
    assert DEFAULT_CONFIG['connect_timeout'] == DEFAULT_CONNECT_TIMEOUT
    assert DEFAULT_CONFIG['read_timeout'] == DEFAULT_READ_TIMEOUT
    assert DEFAULT_CONFIG['max_retries'] == DEFAULT_MAX_RETRIES


def test_build_boto_config_defaults_without_manager():
    """build_boto_config() falls back to the module defaults with no manager."""
    cfg = build_boto_config()
    assert cfg.connect_timeout == DEFAULT_CONNECT_TIMEOUT
    assert cfg.read_timeout == DEFAULT_READ_TIMEOUT
    assert cfg.retries['max_attempts'] == DEFAULT_MAX_RETRIES


def test_build_boto_config_reads_from_manager(tmp_path):
    """build_boto_config reads the configured timeouts and retries."""
    cm = _write_config(tmp_path, """
        default:
          connect_timeout: 5
          read_timeout: 10
          max_retries: 1
    """)
    cfg = build_boto_config(cm)
    assert cfg.connect_timeout == 5
    assert cfg.read_timeout == 10
    assert cfg.retries['max_attempts'] == 1


def test_invalid_timeout_rejected(tmp_path):
    """A non-positive timeout fails config validation."""
    from kosty.core.exceptions import ConfigValidationError
    with pytest.raises(ConfigValidationError):
        _write_config(tmp_path, """
            default:
              connect_timeout: 0
        """)


# ---------------------------------------------------------------------------
# save-to confinement
# ---------------------------------------------------------------------------

def test_confine_local_path_accepts_in_cwd(tmp_path, monkeypatch):
    """A path inside the cwd resolves without raising."""
    monkeypatch.chdir(tmp_path)
    result = confine_local_path("reports/out.json")
    assert str(result).startswith(str(tmp_path.resolve()))


def test_confine_local_path_rejects_outside_cwd(tmp_path, monkeypatch):
    """A path escaping the cwd is refused by default."""
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    with pytest.raises(SaveLocationError):
        confine_local_path("../escape.json")


def test_confine_local_path_opt_out(tmp_path, monkeypatch):
    """allow_outside_cwd lifts the confinement check."""
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    result = confine_local_path("../escape.json", allow_outside_cwd=True)
    assert result == (tmp_path / "escape.json").resolve()


def test_save_to_allow_outside_config_key(tmp_path):
    """The save_to_allow_outside config key is accepted and validated as bool."""
    cm = _write_config(tmp_path, """
        default:
          save_to_allow_outside: true
    """)
    assert cm.get('save_to_allow_outside') is True
