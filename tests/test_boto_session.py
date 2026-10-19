"""Offline tests for the TimeoutClientSession proxy (FEAT-001 seam).

No boto3/STS/network: the wrapped session is a MagicMock whose .client is never
called against AWS, and build_boto_config only constructs a botocore Config
object. The ConfigManager is built from a kosty.yaml under tmp_path, matching
test_config_exclusions.py.
"""

import textwrap

from unittest.mock import MagicMock

from kosty.core.config import ConfigManager, build_boto_config
from kosty.providers.aws.boto_session import TimeoutClientSession, wrap_session


def _config_manager(tmp_path, body: str) -> ConfigManager:
    config_file = tmp_path / "kosty.yaml"
    config_file.write_text(textwrap.dedent(body))
    return ConfigManager(config_file=str(config_file))


# ---------------------------------------------------------------------------
# (a) the proxy injects the configured botocore Config into .client()
# ---------------------------------------------------------------------------

def test_client_injects_timeout_config(tmp_path):
    """client() forwards a config= built from the ConfigManager's timeout keys."""
    cm = _config_manager(tmp_path, """
        default:
          connect_timeout: 5
          read_timeout: 10
          max_retries: 1
    """)
    wrapped = MagicMock()
    proxy = TimeoutClientSession(wrapped, cm)

    proxy.client("ec2", region_name="us-east-1")

    assert wrapped.client.call_count == 1
    args, kwargs = wrapped.client.call_args
    assert args == ("ec2",)
    assert kwargs["region_name"] == "us-east-1"

    injected = kwargs["config"]
    expected = build_boto_config(cm)
    assert injected.connect_timeout == expected.connect_timeout == 5
    assert injected.read_timeout == expected.read_timeout == 10
    assert injected.retries["max_attempts"] == expected.retries["max_attempts"] == 1


# ---------------------------------------------------------------------------
# (b) a caller-supplied config= is preserved (setdefault does not overwrite)
# ---------------------------------------------------------------------------

def test_client_preserves_caller_config(tmp_path):
    """A caller-passed config= is kept; the proxy does not overwrite it."""
    cm = _config_manager(tmp_path, "default: {}")
    wrapped = MagicMock()
    proxy = TimeoutClientSession(wrapped, cm)

    sentinel = object()
    proxy.client("ec2", region_name="us-east-1", config=sentinel)

    _, kwargs = wrapped.client.call_args
    assert kwargs["config"] is sentinel


# ---------------------------------------------------------------------------
# (c) wrap_session is idempotent
# ---------------------------------------------------------------------------

def test_wrap_session_idempotent(tmp_path):
    """wrap_session on an already-wrapped session returns the same object."""
    cm = _config_manager(tmp_path, "default: {}")
    once = wrap_session(MagicMock(), cm)
    twice = wrap_session(once, cm)
    assert twice is once


def test_wrap_session_wraps_raw_session():
    """wrap_session wraps a raw session in a TimeoutClientSession."""
    raw = MagicMock()
    wrapped = wrap_session(raw)
    assert isinstance(wrapped, TimeoutClientSession)
    assert wrapped is not raw


# ---------------------------------------------------------------------------
# (d) non-client attribute access delegates to the wrapped session
# ---------------------------------------------------------------------------

def test_non_client_attribute_delegates():
    """Accessing a non-client attribute forwards to the wrapped session."""
    wrapped = MagicMock()
    wrapped.get_credentials.return_value = "creds"
    wrapped.region_name = "eu-west-3"
    proxy = TimeoutClientSession(wrapped, None)

    assert proxy.get_credentials() == "creds"
    assert proxy.region_name == "eu-west-3"
    wrapped.get_credentials.assert_called_once_with()
