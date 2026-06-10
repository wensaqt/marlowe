"""Custom exception hierarchy for Marlowe."""


class MarloweError(Exception):
    """Base exception for all Marlowe errors."""


class TargetUnreachableError(MarloweError):
    """Target LLM API is unreachable or returned an unexpected error."""


class TargetTimeoutError(MarloweError):
    """Target did not respond within the configured timeout."""


class PluginLoadError(MarloweError):
    """Failed to load or instantiate an attack plugin."""


class PluginNotFoundError(MarloweError):
    """Requested plugin ID is not registered."""


class AnalysisError(MarloweError):
    """An error occurred during response analysis."""


class PersistenceError(MarloweError):
    """An error occurred during database read/write."""


class ConfigurationError(MarloweError):
    """Invalid or missing configuration."""


class BaselineError(MarloweError):
    """Failed to establish a baseline profile for the target."""
