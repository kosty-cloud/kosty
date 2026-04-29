"""Plugin Loader — discovers and imports check modules from search paths.

Supports multiple search paths for OSS/Pro gating:
- OSS mode: loads from providers/aws/services/ only
- SaaS mode: loads from providers/aws/services/ + plugins/pro/

Plugin loading failures are isolated. A broken plugin logs a warning
but does not crash the scan.
"""

import os
import sys
import importlib
import importlib.util
from typing import List, Optional
from pathlib import Path


class PluginLoader:
    """Scans directories for Python modules and imports them.

    On import, modules that use @register_check will self-register
    into the global CheckRegistry. The loader doesn't need to know
    what's inside the modules — it just triggers the import.
    """

    def __init__(self):
        self._loaded_paths: List[str] = []
        self._errors: List[str] = []

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
            return 0

        if path in self._loaded_paths:
            return 0

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
        return loaded

    def load_legacy_services(self, services_dir: str) -> int:
        """Import legacy *_audit.py service files.

        This is the bridge between the old architecture and the new one.
        Legacy services don't use @register_check, so they're loaded
        for the adapter layer to wrap them.

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
        """Import a single module by file path.

        Args:
            filepath: Absolute path to the .py file.
            module_name: Fully qualified module name.

        Returns:
            True if import succeeded, False otherwise.
        """
        try:
            if module_name in sys.modules:
                return True

            spec = importlib.util.spec_from_file_location(module_name, filepath)
            if spec is None or spec.loader is None:
                return False

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            return True

        except Exception as e:
            self._errors.append(f"Failed to load {filepath}: {e}")
            return False

    @property
    def errors(self) -> List[str]:
        """Plugin loading errors (non-fatal)."""
        return self._errors

    @property
    def loaded_paths(self) -> List[str]:
        """Directories that have been scanned."""
        return self._loaded_paths
