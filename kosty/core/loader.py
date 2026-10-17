"""Plugin Loader — discovers and imports check modules from search paths.

Supports multiple search paths for OSS/Pro gating:
- OSS mode: loads from kosty/providers/aws/services/ only
- Pro mode: adds plugins/pro/ as a second path

Plugin loading failures are isolated. A broken plugin logs a warning
but does not crash the scan. Duplicate check_ids are detected and reported.

Security note — plugin execution model:
    exec_module() runs arbitrary Python code with the same privileges as the
    Kosty process, which typically holds live AWS credentials. This is
    intentional: plugins need boto3 access to call AWS APIs.

    The implication is that the providers/ directory is part of the trust
    boundary. Treat it like any other executable code in your project:
    - Keep it under version control
    - Review changes before merging
    - Ensure the directory is not world-writable on shared systems
      (chmod 755 providers/ is the right posture)

    For the Pro version, plugin integrity is verified against a signed
    manifest before loading. The OSS version relies on standard VCS
    controls and file system permissions.
"""

import os
import sys
import hashlib
import importlib
import importlib.util
from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class LoadResult:
    """Summary of a plugin loading operation."""
    loaded: int = 0
    failed: int = 0
    errors: List[str] = field(default_factory=list)


class PluginLoader:
    """Scans directories for Python modules and imports them.

    On import, modules that use @register_check will self-register
    into the global CheckRegistry. The loader doesn't need to know
    what's inside the modules — it just triggers the import.
    """

    def __init__(self):
        self._loaded_paths: List[str] = []
        self._errors: List[str] = []
        self._warnings: List[str] = []
        self._loaded_modules: Dict[str, str] = {}  # module_name -> filepath
        self._manifest: Optional[Dict[str, str]] = None  # rel_path -> sha256
        self._manifest_root: Optional[str] = None  # directory the manifest was loaded from
        self._strict: bool = False

    def load_directory(self, path: str, package_prefix: str = "kosty_plugins", debug: bool = False, strict: bool = False) -> int:
        """Recursively import all .py files from a directory.

        Args:
            path: Absolute or relative path to scan.
            package_prefix: Module namespace prefix for imported modules.
            debug: Print each loaded module and any integrity warnings to stderr.
            strict: When True, refuse plugins that are present on disk but absent
                    from the manifest. Default False keeps local contributors
                    unblocked by a stale manifest (warn and allow).

        Returns:
            Number of modules successfully loaded.
        """
        import sys
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            self._errors.append(f"Directory not found: {path}")
            return 0

        if path in self._loaded_paths:
            return 0

        self._strict = strict
        self._manifest = self._load_manifest(path)
        if self._manifest is not None:
            self._manifest_root = path
        if debug:
            if self._manifest is not None:
                print(f"[DEBUG] loader: manifest loaded ({len(self._manifest)} entries) from {path}", file=sys.stderr)
            else:
                print(f"[DEBUG] loader: no manifest found in {path}", file=sys.stderr)

        from .registry import registry
        loaded = 0
        for root, _dirs, files in os.walk(path):
            for filename in sorted(files):
                if not filename.endswith('.py') or filename.startswith('__'):
                    continue

                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, path)
                module_name = f"{package_prefix}.{rel_path[:-3].replace(os.sep, '.')}"

                if self._import_module(filepath, module_name, debug=debug):
                    loaded += 1
                    if debug:
                        print(f"[DEBUG] loader: loaded {rel_path}", file=sys.stderr)

        self._loaded_paths.append(path)
        self._detect_duplicates(registry)

        if debug:
            print(
                f"[DEBUG] loader: {loaded} modules loaded, "
                f"{len(self._errors)} errors, {len(self._warnings)} warnings",
                file=sys.stderr,
            )

        return loaded


    def _load_manifest(self, plugins_dir: str) -> Optional[Dict[str, str]]:
        """Load plugins.sha256 from the plugins directory if it exists.

        Returns a dict mapping relative path -> expected hex digest,
        or None if no manifest is present (verification is skipped).
        """
        manifest_path = os.path.join(plugins_dir, 'plugins.sha256')
        if not os.path.exists(manifest_path):
            return None

        manifest = {}
        try:
            with open(manifest_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    # Tolerant parsing: sha256sum emits "<digest>  <path>" (two
                    # spaces) in text mode and "<digest> *<path>" in binary mode,
                    # and some tools use a tab. Split on the first run of
                    # whitespace and drop a leading '*' binary-mode marker.
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        digest, rel_path = parts
                        rel_path = rel_path.lstrip('*')
                        manifest[rel_path] = digest
        except Exception as e:
            self._errors.append(f"Failed to read manifest: {e}")
            return None

        return manifest

    def _verify_plugin(self, filepath: str) -> bool:
        """Check the plugin's SHA-256 against the manifest.

        Returns True if the plugin passes (or if no manifest is loaded).
        Surfaces a warning for plugins not listed in the manifest, and an
        error for hash mismatches — those are refused outright. In strict
        mode an unlisted plugin is refused as well.

        The relative path is computed against the directory the manifest was
        loaded from (self._manifest_root), so manifest lookups do not depend on
        where in the tree an individual file lives.
        """
        if self._manifest is None or self._manifest_root is None:
            return True

        rel_path = os.path.relpath(filepath, self._manifest_root)
        expected = self._manifest.get(rel_path)

        if expected is None:
            # Plugin exists on disk but isn't in the manifest.
            name = os.path.basename(filepath)
            if self._strict:
                self._errors.append(
                    f"Refused {name}: not in manifest (strict mode) — "
                    f"run scripts/generate_manifest.py"
                )
                return False
            # Default: warn but allow — contributors adding new checks locally
            # shouldn't be blocked by a stale manifest. Surface it as a warning
            # so the engine/CLI can show it, not just under --debug.
            self._warnings.append(
                f"{name} not in manifest — run scripts/generate_manifest.py before release"
            )
            return True

        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        actual = h.hexdigest()

        if actual != expected:
            self._errors.append(
                f"Integrity check failed: {os.path.basename(filepath)} "
                f"(expected {expected[:12]}..., got {actual[:12]}...)"
            )
            return False

        return True

    def _import_module(self, filepath: str, module_name: str, debug: bool = False) -> bool:
        """Import a single module by file path with isolation.

        Args:
            filepath: Absolute path to the .py file.
            module_name: Fully qualified module name.
            debug: Print integrity check results to stderr.

        Returns:
            True if import succeeded, False otherwise.
        """
        # Skip if already loaded
        if module_name in sys.modules:
            return True

        # Skip if file is empty or too small to contain a check
        try:
            size = os.path.getsize(filepath)
            if size < 50:
                return False
        except OSError:
            return False

        # Verify integrity against manifest before executing any code.
        # rel_path is resolved against the manifest root recorded in
        # load_directory, so we don't walk the tree to re-discover it.
        if not self._verify_plugin(filepath):
            return False

        try:
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            if spec is None or spec.loader is None:
                self._errors.append(f"Cannot create spec for {filepath}")
                return False

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module

            try:
                spec.loader.exec_module(module)
            except Exception as e:
                # Rollback: remove from sys.modules on failure
                del sys.modules[module_name]
                self._errors.append(f"Failed to exec {os.path.basename(filepath)}: {type(e).__name__}: {e}")
                return False

            self._loaded_modules[module_name] = filepath
            return True

        except Exception as e:
            self._errors.append(f"Failed to load {os.path.basename(filepath)}: {type(e).__name__}: {e}")
            return False

    def _detect_duplicates(self, registry):
        """Check for duplicate check_ids in the registry."""
        seen = {}
        for check in registry.get_all_checks():
            cid = check['metadata'].check_id
            func_module = getattr(check['func'], '__module__', 'unknown')
            if cid in seen and seen[cid] != func_module:
                self._errors.append(
                    f"Duplicate check_id '{cid}' in {func_module} (first seen in {seen[cid]})"
                )
            else:
                seen[cid] = func_module

    def get_load_summary(self) -> LoadResult:
        """Return structured summary of loading operations."""
        return LoadResult(
            loaded=len(self._loaded_modules),
            failed=len(self._errors),
            errors=list(self._errors),
        )

    @property
    def errors(self) -> List[str]:
        """Plugin loading errors (non-fatal)."""
        return self._errors

    @property
    def warnings(self) -> List[str]:
        """Non-fatal plugin warnings (e.g. a file missing from the manifest)."""
        return self._warnings

    @property
    def loaded_paths(self) -> List[str]:
        """Directories that have been scanned."""
        return self._loaded_paths

    @property
    def loaded_count(self) -> int:
        """Number of modules successfully loaded."""
        return len(self._loaded_modules)
