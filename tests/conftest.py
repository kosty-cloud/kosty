"""Shared pytest fixtures for offline plugin-loading tests.

Strictly offline: loading a check module runs its @register_check decorator
only — no boto3 client is constructed and no network/STS call is made. The
fixtures here are opt-in (not autouse) so existing tests keep their current
behavior; a test that wants deterministic plugin state requests them by name.
"""

import os
import sys

import pytest

from kosty.core.registry import registry
from kosty.core.loader import PluginLoader


# Module-namespace prefix the native check files import under. Evicting these
# from sys.modules lets a subsequent load_directory re-execute them, which
# re-runs their @register_check against the (freshly cleared) registry.
_SERVICES_PREFIX = 'kosty.providers.aws.services'


def _services_dir() -> str:
    """Absolute path to the native plugin directory kosty/providers/aws/services."""
    here = os.path.dirname(__file__)
    return os.path.abspath(
        os.path.join(here, '..', 'kosty', 'providers', 'aws', 'services')
    )


def _evict_service_modules() -> None:
    """Drop every imported native check module from sys.modules.

    Registration is a side effect of importing a check module. Once a module is
    in sys.modules, neither a native `import` nor the loader re-executes it, so
    clearing only registry._checks would leave the registry empty with no way to
    repopulate it. Evicting the modules forces the next import/load to execute
    the file again and re-register its checks.
    """
    for name in [m for m in sys.modules if m.startswith(_SERVICES_PREFIX)]:
        del sys.modules[name]


@pytest.fixture
def clean_registry():
    """Snapshot and restore the global registry so tests don't leak checks.

    Clears registry._checks AND registry._warnings so each test starts from a
    deterministic empty state, and evicts the native check modules so a
    subsequent load repopulates the registry instead of short-circuiting on an
    already-imported module. Mirrors the snapshot/restore style used in
    test_engine_run_service.py.
    """
    saved_checks = dict(registry._checks)
    saved_warnings = list(registry._warnings)
    registry._checks.clear()
    registry._warnings.clear()
    _evict_service_modules()
    try:
        yield registry
    finally:
        registry._checks.clear()
        registry._checks.update(saved_checks)
        registry._warnings.clear()
        registry._warnings.extend(saved_warnings)


@pytest.fixture(scope="session")
def loaded_registry():
    """Load the real services directory once per session under a fresh loader.

    Offline: importing the check modules only executes their decorators.
    Yields the loader so tests can read its warnings/errors.
    """
    loader = PluginLoader()
    loader.load_directory(_services_dir())
    yield loader
