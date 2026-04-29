"""Plugin Loader — discovers and imports check modules from search paths.

Supports multiple search paths for OSS/Pro gating:
- OSS mode: loads from kosty/providers/aws/services/ only
- SaaS mode: adds plugins/pro/ as a second path

Plugin loading failures are isolated. A broken plugin logs a warning
but does not crash the scan. Duplicate check_ids are detected and reported.
"""

import os
import sys
import importlib
import importlib.util
import signal
from typing import List, Dict, Any
from dataclasses import dataclass, field


@dataclass
class LoadResult:
    """Summary of a plugin loading operation."""
    loaded: int = 0
    skipped: int = 0
    failed: int = 0
    errors: List[str] = field(default_factory=list)
    duplicates: List[str] = field(default_factory=list)


class PluginLoader:
    """Scans directories for Python modules and imports them.

    On import, modules that use @register_check will self-register
    into the global CheckRegistry. The loader doesn't need to know
    what's inside the modules — it just triggers the import.
    """

    def __init__(self, timeout_seconds: int = 10):
        self._loaded_paths: List[str] = []
        self._errors: List[str] = []
        self._loaded_modules: Dict[str, str] = {}  # module_name -> filepath
        self._timeout = timeout_seconds

    def load_directory(self, path: str, package_prefix: str = "kosty_plugins") -> int:
        """Recursively import all .py files from a directory.

        Args:
            path: Absolute or relative path to scan.
            package_prefix: Module namespace prefix for imported modules.

        Returns:
            Number of modules successfully loaded.
        """
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            self._errors.append(f"Directory not found: {path}")
            return 0

        if path in self._loaded_paths:
            return 0

        from .registry import registry
        before_count = registry.count

        loaded = 0
        for root, _dirs, files in os.walk(path):
            for filename in sorted(files):
                if not filename.endswith('.py') or filename.startswith('__'):
                    continue

                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, path)
                module_name = f"{package_prefix}.{rel_path[:-3].replace(os.sep, '.')}"

                if self._import_module(filepath, module_name):
                    loaded += 1

        self._loaded_paths.append(path)

        # Detect duplicate check_ids
        self._detect_duplicates(registry)

        return loaded

    def load_legacy_services(self, services_dir: str) -> int:
        """Import legacy *_audit.py service files.

        Args:
            services_dir: Path to kosty/services/ directory.

        Returns:
            Number of modules successfully loaded.
        """
        services_dir = os.path.abspath(services_dir)
        if not os.path.isdir(services_dir):
            return 0

        loaded = 0
        for filename in sorted(os.listdir(services_dir)):
            if not filename.endswith('_audit.py') or filename.startswith('__'):
                continue

            filepath = os.path.join(services_dir, filename)
            module_name = f"kosty.services.{filename[:-3]}"

            if self._import_module(filepath, module_name):
                loaded += 1

        return loaded

    def _import_module(self, filepath: str, module_name: str) -> bool:
        """Import a single module by file path with isolation.

        Args:
            filepath: Absolute path to the .py file.
            module_name: Fully qualified module name.

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
    def loaded_paths(self) -> List[str]:
        """Directories that have been scanned."""
        return self._loaded_paths

    @property
    def loaded_count(self) -> int:
        """Number of modules successfully loaded."""
        return len(self._loaded_modules)
