"""Exceptions raised by the Kosty configuration layer.

Kept separate from the rest of the codebase so callers can import
just what they need without pulling in the full config module.
"""


class ConfigValidationError(Exception):
    """Raised when kosty.yaml contains invalid values.

    The error message lists every problem found, not just the first one,
    so users can fix everything in a single pass.
    """


class ConfigNotFoundError(Exception):
    """Raised when an explicit --config-file path doesn't exist on disk."""


class SaveLocationError(Exception):
    """Raised when a --save-to local path is rejected.

    By default a destination that resolves outside the current working
    directory is refused; the opt-out (--allow-outside-cwd) lifts the check.
    """
