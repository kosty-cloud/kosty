"""Offline tests for kosty.providers.aws.session_utils._session_key.

No boto3/STS/network: the session is a MagicMock whose get_credentials()
returns a hand-built credentials object, and get_account_id is not called.
"""

import hashlib
from unittest.mock import MagicMock

from kosty.providers.aws.session_utils import _session_key


class _FakeCreds:
    """Stand-in for botocore frozen credentials with an access key + token."""

    def __init__(self, access_key: str, token=None):
        self.access_key = access_key
        self.token = token

    def resolve(self):
        return self


def _session_with_access_key(access_key: str, token=None) -> MagicMock:
    session = MagicMock()
    session.get_credentials.return_value = _FakeCreds(access_key, token)
    return session


def test_session_key_uses_sha256_digest_not_raw_prefix():
    """The key embeds a sha256[:12] digest, never the raw AKIA/ASIA prefix."""
    access_key = "AKIAIOSFODNN7EXAMPLE"
    session = _session_with_access_key(access_key)
    key = _session_key(session)

    expected_digest = hashlib.sha256(access_key.encode()).hexdigest()[:12]
    assert key == f"{expected_digest}:0"
    assert "AKIA" not in key
    assert access_key not in key


def test_session_key_token_flag_distinguishes_sessions():
    """The token flag differs between a static key and a session token."""
    access_key = "AKIAIOSFODNN7EXAMPLE"
    no_token = _session_key(_session_with_access_key(access_key))
    with_token = _session_key(_session_with_access_key(access_key, token="FwoGZXIvYXdz"))
    assert no_token.endswith(":0")
    assert with_token.endswith(":1")
    assert no_token != with_token


def test_session_key_falls_back_to_object_id_without_credentials():
    """When no credentials resolve, the key falls back to str(id(session))."""
    session = MagicMock()
    session.get_credentials.return_value = None
    key = _session_key(session)
    assert key == str(id(session))


def test_session_key_falls_back_when_resolve_raises():
    """A failure resolving credentials falls back to the id-based key."""
    session = MagicMock()
    session.get_credentials.side_effect = RuntimeError("no creds")
    assert _session_key(session) == str(id(session))
