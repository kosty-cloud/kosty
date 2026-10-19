"""Regression test for the duplicate plugin-loading bug.

Before v3.6.1 the loader imported every check file under a synthetic
`kosty_plugins.*` module name, distinct from the native
`kosty.providers.aws.services.*` path the test suite imports directly. The
same file then executed its @register_check decorator twice (once per module
identity), which the registry reported as a "Duplicate check_id" warning.

These tests lock in the fix: in-tree checks are imported under their real
package path, so the direct import and the directory load resolve to a single
module identity and register exactly once.

Strictly offline: loading runs decorators only, no boto3/STS/network.
"""

import os

from kosty.core.loader import PluginLoader
from kosty.core.registry import registry


def _services_dir() -> str:
    here = os.path.dirname(__file__)
    return os.path.abspath(
        os.path.join(here, '..', 'kosty', 'providers', 'aws', 'services')
    )


def test_loading_services_dir_does_not_double_register(clean_registry):
    """Loading the real services directory produces no duplicate-check_id warning."""
    loader = PluginLoader()
    loader.load_directory(_services_dir())

    assert loader.loaded_count > 0
    assert not any('Duplicate check_id' in w for w in registry.warnings)
    assert not any('Duplicate check_id' in e for e in loader.errors)


def test_direct_import_and_loader_share_one_identity(clean_registry):
    """A direct native import and the directory load register the check once."""
    from kosty.providers.aws.services.ebs.check_orphan_volumes import (
        check_orphan_volumes,
    )

    assert (
        check_orphan_volumes.__module__
        == "kosty.providers.aws.services.ebs.check_orphan_volumes"
    )

    loader = PluginLoader()
    loader.load_directory(_services_dir())

    # The native import already placed the module in sys.modules under its real
    # name, so the directory load reuses that single identity instead of
    # re-executing the file under a synthetic name.
    assert not any('Duplicate check_id' in w for w in registry.warnings)
    entry = registry.get_check("aws-ebs-001")
    assert entry is not None
    assert (
        entry['func'].__module__
        == "kosty.providers.aws.services.ebs.check_orphan_volumes"
    )
