"""Shared pytest fixtures for offline plugin-loading tests.

Strictly offline: loading a check module runs its @register_check decorator
only — no boto3 client is constructed and no network/STS call is made. The
fixtures here are opt-in (not autouse) so existing tests keep their current
behavior; a test that wants deterministic plugin state requests them by name.
"""

import os

import pytest

from kosty.core.registry import registry
from kosty.core.loader import PluginLoader


def _services_dir() -> str:
    """Absolute path to the native plugin directory kosty/providers/aws/services."""
    here = os.path.dirname(__file__)
    return os.path.abspath(
        os.path.join(here, '..', 'kosty', 'providers', 'aws', 'services')
    )


@pytest.fixture
def clean_registry():
    """Snapshot and restore the global registry so tests don't leak checks.

    Mirrors the snapshot/restore style used in test_engine_run_service.py.
    """
    saved = dict(registry._checks)
    registry._checks.clear()
    try:
        yield registry
    finally:
        registry._checks.clear()
        registry._checks.update(saved)


@pytest.fixture(scope="session")
def loaded_registry():
    """Load the real services directory once per session under a fresh loader.

    Offline: importing the check modules only executes their decorators.
    Yields the loader so tests can read its warnings/errors.
    """
    loader = PluginLoader()
    loader.load_directory(_services_dir())
    yield loader
