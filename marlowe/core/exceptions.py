"""Custom exception hierarchy for Marlowe."""


class MarloweError(Exception):
    """Base exception for all Marlowe errors."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class ConfigurationError(MarloweError):
    """Invalid or missing configuration."""


# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------


class TargetError(MarloweError):
    """Base exception for target connectivity issues."""


class TargetUnreachableError(TargetError):
    """Target LLM API is unreachable or returned an unexpected error."""


class TargetTimeoutError(TargetError):
    """Target did not respond within the configured timeout."""


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class PluginError(MarloweError):
    """Base exception for plugin-related issues."""


class PluginNotFoundError(PluginError):
    """Requested plugin ID is not registered."""


class PluginLoadError(PluginError):
    """Failed to load or instantiate an attack plugin via entry points."""


# ---------------------------------------------------------------------------
# Variant
# ---------------------------------------------------------------------------


class VariantError(MarloweError):
    """Base exception for single-variant execution failures."""


class VariantGenerationError(VariantError):
    """Plugin failed to generate its attack variants."""


class VariantExecutionError(VariantError):
    """Network or transport error while sending a variant to the target."""


class VariantAnalysisError(VariantError):
    """Plugin raised an exception while analysing a target response."""


# ---------------------------------------------------------------------------
# Other
# ---------------------------------------------------------------------------


class BaselineError(MarloweError):
    """Failed to establish a baseline profile for the target."""


class PersistenceError(MarloweError):
    """An error occurred during database read/write."""
