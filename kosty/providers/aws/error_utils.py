"""Permission-error handling for AWS check plugins.

Checks run read-only against AWS and routinely hit APIs the caller has no
permission for. Historically every check wrapped its body in
``except Exception: pass`` (or ``continue``), which silently turned a missing
permission into an empty result — indistinguishable from "scanned, nothing
found". That hid real coverage gaps from the user.

Convention
----------
A check NEVER crashes the scan. It still catches ``Exception`` around its AWS
calls, but instead of unconditionally swallowing, it classifies the error:

- **Permission error** (AccessDenied / UnauthorizedOperation / AuthFailure):
  the check re-raises it. Both execution paths capture it — ``ScanEngine`` routes
  it to ``ScanResult.errors`` (``core/engine.py``) and the per-service CLI path
  records it in the error list surfaced by ``cli/utils._run_checks``. The user
  then sees "N check(s) could not complete (e.g. missing permissions)" instead
  of a false "no issues found".
- **Any other error** (malformed API response, unexpected shape, transient
  glitch, a resource that vanished mid-scan): still swallowed exactly as before.
  The check returns the findings gathered so far and the scan continues.

Usage in a check::

    from kosty.providers.aws.error_utils import handle_check_error

    try:
        ... AWS calls ...
    except Exception as exc:
        handle_check_error(exc)   # re-raises permission errors, else returns
        # non-permission error contained — fall through / return findings

For per-resource loops where the original code did ``continue``::

    for item in items:
        try:
            ... per-item AWS calls ...
        except Exception as exc:
            handle_check_error(exc)  # permission error surfaces; else skip item
            continue

``handle_check_error`` is the single choke point so the convention stays
uniform across all ~120 check files.
"""

from typing import Any

# botocore error codes that mean "the caller lacks permission", not "nothing found".
PERMISSION_ERROR_CODES = frozenset({
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthFailure",
})


def is_permission_error(exc: BaseException) -> bool:
    """Return True if an exception represents an AWS permission denial.

    Recognizes botocore ``ClientError`` by its ``Error.Code`` and falls back to
    a substring match on the string form so wrapped or re-raised errors are
    still caught.

    Args:
        exc: The caught exception.

    Returns:
        True when the error is an AccessDenied/UnauthorizedOperation/AuthFailure.
    """
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if code in PERMISSION_ERROR_CODES:
            return True
    text = str(exc)
    return any(code in text for code in PERMISSION_ERROR_CODES)


def handle_check_error(exc: Exception) -> None:
    """Apply the shared check error convention: surface permission errors, contain the rest.

    Re-raises ``exc`` when it is a permission error so the engine/CLI error
    channel records it; returns silently for any other error so the caller can
    swallow it (``pass``/``continue``) and keep the scan running.

    Args:
        exc: The exception caught inside a check.

    Raises:
        Exception: the original ``exc`` when it is a permission error.
    """
    if is_permission_error(exc):
        raise exc
