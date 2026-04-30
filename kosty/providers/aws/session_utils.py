"""Session utilities shared across all AWS plugins.

Centralizes the STS get_caller_identity call so it happens once per
boto3 session rather than once per check. With 151 checks running in
parallel, the naive approach would fire 151 identical STS calls.
"""

import threading
from typing import Any

_cache: dict = {}
_lock = threading.Lock()


def get_account_id(session: Any) -> str:
    """Return the AWS account ID for a session, cached per session object.

    Uses the session object's id() as the cache key. Safe for concurrent
    use — the lock ensures only one STS call per unique session.

    Args:
        session: A boto3.Session instance.

    Returns:
        12-digit AWS account ID string.
    """
    key = id(session)
    if key in _cache:
        return _cache[key]

    with _lock:
        # Double-checked locking: another thread may have populated it
        if key not in _cache:
            _cache[key] = session.client('sts').get_caller_identity()['Account']
    return _cache[key]
