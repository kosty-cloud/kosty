"""Session proxy that wires build_boto_config into client creation.

The ~150 check functions call ``session.client('svc', region_name=region)``
directly on a raw boto3 Session, so the botocore Config built by
``build_boto_config`` (connect/read timeouts, retries) never reached the
clients. Wrapping the session once at the engine's per-check boundary lets
those timeouts take effect without touching any check.

The proxy only injects ``config=`` when the caller did not pass one, and
delegates every other attribute (get_credentials, region_name, the sts client
used by session_utils.get_account_id, ...) straight to the wrapped session.
"""

from typing import Any

from kosty.core.config import build_boto_config


class TimeoutClientSession:
    """Wrap a boto3 Session so .client() gets the configured botocore Config.

    All attribute access other than ``client`` is delegated to the wrapped
    session, so the proxy is a transparent stand-in anywhere a boto3 Session
    is expected.
    """

    def __init__(self, session: Any, config_manager: Any = None):
        self._session = session
        self._config_manager = config_manager

    def client(self, *args, **kwargs):
        """Create a client, injecting the timeout Config unless one was given."""
        kwargs.setdefault('config', build_boto_config(self._config_manager))
        return self._session.client(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        """Delegate any other attribute to the wrapped session."""
        return getattr(self._session, name)


def wrap_session(session: Any, config_manager: Any = None) -> Any:
    """Return a TimeoutClientSession wrapping session, idempotently.

    An already-wrapped session is returned unchanged so org-mode assumed
    sessions and the sts client inside get_account_id are never double-wrapped.
    """
    if isinstance(session, TimeoutClientSession):
        return session
    return TimeoutClientSession(session, config_manager)
