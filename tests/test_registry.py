"""Offline tests for kosty.core.registry duplicate check_id handling.

No boto3/STS/network: a fresh CheckRegistry is built per test so the global
singleton is untouched, and check functions are trivial stubs.
"""

import warnings

from kosty.core.registry import CheckRegistry
from kosty.core.models import FindingType


def _register(reg: CheckRegistry, check_id: str, module: str):
    """Register a stub check under check_id with a given __module__."""
    def check(session, region, **kwargs):
        return []
    check.__module__ = module
    return reg.register(
        check_id=check_id,
        service="EC2",
        provider="aws",
        finding_type=FindingType.COST,
    )(check)


def test_register_single_check():
    """A single registration lands in the registry with its metadata."""
    reg = CheckRegistry()
    _register(reg, "aws-ec2-001", "mod.a")
    assert reg.count == 1
    assert reg.get_check("aws-ec2-001")['metadata'].check_id == "aws-ec2-001"
    assert reg.warnings == []


def test_duplicate_check_id_surfaces_warning():
    """A second registration of the same id appends a registry warning."""
    reg = CheckRegistry()
    _register(reg, "aws-ec2-001", "mod.a")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _register(reg, "aws-ec2-001", "mod.b")
    assert len(reg.warnings) == 1
    assert "aws-ec2-001" in reg.warnings[0]
    assert "mod.b" in reg.warnings[0] and "mod.a" in reg.warnings[0]
    assert any("aws-ec2-001" in str(w.message) for w in caught)


def test_duplicate_check_id_does_not_drop_silently():
    """The duplicate overwrites but is never silent — count stays 1, warned once."""
    reg = CheckRegistry()
    _register(reg, "aws-ec2-001", "mod.a")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        _register(reg, "aws-ec2-001", "mod.b")
    assert reg.count == 1
    assert len(reg.warnings) == 1
    # the later registration wins (new module recorded)
    assert reg.get_check("aws-ec2-001")['func'].__module__ == "mod.b"


def test_distinct_ids_do_not_warn():
    """Different check_ids coexist without any warning."""
    reg = CheckRegistry()
    _register(reg, "aws-ec2-001", "mod.a")
    _register(reg, "aws-ec2-002", "mod.a")
    assert reg.count == 2
    assert reg.warnings == []
