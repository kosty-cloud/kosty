"""Custom exceptions for Kosty configuration system"""


class ConfigValidationError(Exception):
    """Raised when configuration validation fails"""
    pass


class ConfigNotFoundError(Exception):
    """Raised when configuration file is not found"""
    pass
