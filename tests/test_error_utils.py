"""Offline tests for the shared permission-error convention.

No boto3/STS/network: exceptions are constructed by hand to mimic the shape of
a botocore ClientError (an object carrying a .response dict).
"""

import pytest

from kosty.providers.aws.error_utils import (
    is_permission_error,
    handle_check_error,
    PERMISSION_ERROR_CODES,
)


class _FakeClientError(Exception):
    """Mimics botocore.exceptions.ClientError: carries a .response dict."""

    def __init__(self, code: str, message: str = "denied"):
        super().__init__(f"{code}: {message}")
        self.response = {'Error': {'Code': code, 'Message': message}}


@pytest.mark.parametrize("code", sorted(PERMISSION_ERROR_CODES))
def test_is_permission_error_recognizes_each_code(code):
    """Every permission code in the frozenset is recognised via .response."""
    assert is_permission_error(_FakeClientError(code)) is True


def test_is_permission_error_substring_fallback():
    """A bare exception whose text contains a permission code is recognised."""
    assert is_permission_error(Exception("UnauthorizedOperation while calling")) is True


def test_is_permission_error_false_for_other_client_errors():
    """A non-permission ClientError (e.g. throttling) is not a permission error."""
    assert is_permission_error(_FakeClientError('ThrottlingException')) is False


def test_is_permission_error_false_for_plain_errors():
    """Ordinary Python exceptions are not permission errors."""
    assert is_permission_error(ValueError("bad value")) is False
    assert is_permission_error(KeyError("missing")) is False


def test_handle_check_error_reraises_permission_error():
    """handle_check_error re-raises a permission error so the engine records it."""
    exc = _FakeClientError('AccessDenied')
    with pytest.raises(_FakeClientError) as caught:
        handle_check_error(exc)
    assert caught.value is exc


def test_handle_check_error_contains_non_permission_error():
    """handle_check_error returns None for a non-permission error (swallowed)."""
    assert handle_check_error(ValueError("transient")) is None
    assert handle_check_error(_FakeClientError('ThrottlingException')) is None
