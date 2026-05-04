"""Session utilities shared across all AWS plugins.

Centralizes the STS get_caller_identity call so it happens once per
boto3 session rather than once per check. With 151 checks running in
parallel, the naive approach would fire 151 identical STS calls.
"""

import threading
from typing import Any

_lock = threading.Lock()

# WeakValueDictionary can't be used here since sessions aren't weak-referenceable.
# Use a regular dict but key on a stable identity: the session's credentials tuple.
# Falls back to id() for sessions without resolvable credentials (e.g. default chain).
_cache: dict = {}


def _session_key(session: Any) -> str:
    """Derive a stable, GC-safe cache key from the session's resolved credentials."""
    try:
        creds = session.get_credentials()
        if creds:
            resolved = creds.resolve()
            return f"{resolved.access_key}:{resolved.token or ''}"
    except Exception:
        pass
    # Fallback: use object id (may collide after GC, but acceptable for short-lived sessions)
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
