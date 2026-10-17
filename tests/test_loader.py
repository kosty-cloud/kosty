"""Offline tests for kosty.core.loader PluginLoader.

No boto3/STS/network: plugin files and the manifest are written under
tmp_path. Manifest parsing, hash verification, the unlisted-file policy
(permissive default vs strict refusal), and a happy-path directory load are
exercised directly.
"""

import hashlib
import os

from kosty.core.loader import PluginLoader


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _write_plugin(tmp_path, name: str, body: str = "VALUE = 1\n") -> str:
    """Write a plugin file padded past the loader's 50-byte minimum."""
    path = tmp_path / name
    path.write_text(body + "# padding so the file clears the size floor\n")
    return str(path)


# ---------------------------------------------------------------------------
# manifest parsing (tolerant)
# ---------------------------------------------------------------------------

def test_load_manifest_absent_returns_none(tmp_path):
    """No manifest on disk means verification is skipped (returns None)."""
    loader = PluginLoader()
    assert loader._load_manifest(str(tmp_path)) is None


def test_load_manifest_tolerant_parsing(tmp_path):
    """Two-space, binary '*', and tab separators all parse to (digest, path)."""
    manifest = tmp_path / "plugins.sha256"
    manifest.write_text(
        "aaa  check_two_space.py\n"
        "bbb *check_binary.py\n"
        "ccc\tcheck_tab.py\n"
        "\n"
    )
    loader = PluginLoader()
    parsed = loader._load_manifest(str(tmp_path))
    assert parsed == {
        "check_two_space.py": "aaa",
        "check_binary.py": "bbb",
        "check_tab.py": "ccc",
    }


# ---------------------------------------------------------------------------
# _verify_plugin — hash match / mismatch / unlisted policy
# ---------------------------------------------------------------------------

def _loader_with_manifest(tmp_path, manifest: dict, strict: bool = False) -> PluginLoader:
    loader = PluginLoader()
    loader._manifest = manifest
    loader._manifest_root = str(tmp_path)
    loader._strict = strict
    return loader


def test_verify_plugin_accepts_matching_hash(tmp_path):
    """A file whose digest matches the manifest passes."""
    plugin = _write_plugin(tmp_path, "check_ok.py")
    loader = _loader_with_manifest(tmp_path, {"check_ok.py": _sha256_file(plugin)})
    assert loader._verify_plugin(plugin) is True


def test_verify_plugin_refuses_hash_mismatch(tmp_path):
    """A tampered file (wrong digest) is refused in the default mode."""
    plugin = _write_plugin(tmp_path, "check_tampered.py")
    loader = _loader_with_manifest(tmp_path, {"check_tampered.py": "deadbeef"})
    assert loader._verify_plugin(plugin) is False
    assert any("Integrity check failed" in e for e in loader.errors)


def test_verify_plugin_unlisted_permissive_default(tmp_path):
    """An unlisted file is allowed by default but surfaces a warning."""
    plugin = _write_plugin(tmp_path, "check_new.py")
    loader = _loader_with_manifest(tmp_path, {"check_other.py": "abc"}, strict=False)
    assert loader._verify_plugin(plugin) is True
    assert any("not in manifest" in w for w in loader.warnings)


def test_verify_plugin_unlisted_refused_in_strict(tmp_path):
    """An unlisted file is refused in strict mode and recorded as an error."""
    plugin = _write_plugin(tmp_path, "check_new.py")
    loader = _loader_with_manifest(tmp_path, {"check_other.py": "abc"}, strict=True)
    assert loader._verify_plugin(plugin) is False
    assert any("not in manifest" in e for e in loader.errors)


def test_verify_plugin_skipped_without_manifest(tmp_path):
    """With no manifest loaded, verification passes unconditionally."""
    plugin = _write_plugin(tmp_path, "check_any.py")
    loader = PluginLoader()
    assert loader._verify_plugin(plugin) is True


# ---------------------------------------------------------------------------
# load_directory — happy path, no manifest (no network, no boto3)
# ---------------------------------------------------------------------------

def test_load_directory_imports_modules(tmp_path):
    """A directory of trivial modules loads, counting the importable files."""
    _write_plugin(tmp_path, "mod_alpha.py", "ALPHA = 1\n")
    _write_plugin(tmp_path, "mod_beta.py", "BETA = 2\n")

    loader = PluginLoader()
    loaded = loader.load_directory(
        str(tmp_path), package_prefix="kosty_test_plugins_dir"
    )
    assert loaded == 2
    assert loader.loaded_count == 2
    assert str(tmp_path) in [os.path.abspath(p) for p in loader.loaded_paths]


def test_load_directory_missing_dir_records_error(tmp_path):
    """A non-existent directory loads nothing and records an error."""
    loader = PluginLoader()
    missing = str(tmp_path / "does_not_exist")
    assert loader.load_directory(missing, package_prefix="kosty_test_missing") == 0
    assert any("Directory not found" in e for e in loader.errors)
