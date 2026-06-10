"""
Plugin registry.

Discovers attack plugins via Python entry points (pyproject.toml).
Falls back to explicit registration for tests and direct usage.
"""

from __future__ import annotations

from importlib.metadata import entry_points

import structlog

from marlowe.attacks.base import BaseAttackPlugin
from marlowe.core.exceptions import PluginLoadError, PluginNotFoundError

log = structlog.get_logger(__name__)

_ENTRY_POINT_GROUP = "marlowe.attacks"


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, BaseAttackPlugin] = {}

    def discover(self) -> None:
        """Load all plugins registered under the marlowe.attacks entry point group."""
        eps = entry_points(group=_ENTRY_POINT_GROUP)
        for ep in eps:
            try:
                cls = ep.load()
                instance = cls()
                self._plugins[instance.plugin_id] = instance
                log.debug("plugin loaded", plugin=instance.plugin_id)
            except Exception as exc:
                raise PluginLoadError(f"Failed to load plugin '{ep.name}': {exc}") from exc
        log.info("plugins discovered", count=len(self._plugins))

    def register(self, plugin: BaseAttackPlugin) -> None:
        """Manually register a plugin (useful for tests)."""
        self._plugins[plugin.plugin_id] = plugin

    def get(self, plugin_id: str) -> BaseAttackPlugin:
        if plugin_id not in self._plugins:
            raise PluginNotFoundError(
                f"Plugin '{plugin_id}' not found. Available: {self.all_ids()}"
            )
        return self._plugins[plugin_id]

    def all_ids(self) -> list[str]:
        return list(self._plugins.keys())

    def all(self) -> list[BaseAttackPlugin]:
        return list(self._plugins.values())

    def __len__(self) -> int:
        return len(self._plugins)
