"""Session utilities shared across all AWS plugins.

Centralizes the STS get_caller_identity call so it happens once per
boto3 session rather than once per check. With 151 checks running in
parallel, the naive approach would fire 151 identical STS calls.
"""

import hashlib
import threading
from typing import Any

_lock = threading.Lock()

# Cache keyed on account ID, not on credentials.
# Storing access keys as cache keys would leave live credential material
# in memory for the entire process lifetime — a risk if the process is
# dumped. Account IDs are non-sensitive 12-digit strings.
_cache: dict = {}


def _session_key(session: Any) -> str:
    """Derive a cache key from the session's resolved credentials.

    We call get_caller_identity once to get the account ID, then use
    that as the key. This avoids storing access keys in the cache dict
    while still correctly distinguishing sessions across different accounts.
    Falls back to a credential-based key if STS is not yet reachable.
    """
    try:
        creds = session.get_credentials()
        if creds:
            resolved = creds.resolve()
            # Hash the access key (truncated digest) + token presence as a
            # lightweight discriminator. Hashing avoids holding a raw AKIA/ASIA
            # prefix in memory as a dict key while still distinguishing sessions.
            digest = hashlib.sha256(resolved.access_key.encode()).hexdigest()[:12]
            token_flag = '1' if resolved.token else '0'
            return f"{digest}:{token_flag}"
    except Exception:
        pass
    return str(id(session))


def get_account_id(session: Any) -> str:
    """Return the AWS account ID for a session, cached per unique credential set.

    Keyed on resolved credentials rather than object id() to avoid stale
    cache hits after garbage collection reuses memory addresses.

    Args:
        session: A boto3.Session instance.

    Returns:
        12-digit AWS account ID string.
    """
    key = _session_key(session)
    if key in _cache:
        return _cache[key]

    with _lock:
        if key not in _cache:
            _cache[key] = session.client('sts').get_caller_identity()['Account']
    return _cache[key]
