"""
Plugin registry.

Discovers attack plugins via Python entry points (pyproject.toml).
Falls back to explicit registration for tests and direct usage.
"""

from __future__ import annotations

from importlib.metadata import entry_points

import structlog

from marlowe.attacks.base import BaseAttackPlugin
from marlowe.core.exceptions import PluginNotFoundError

log = structlog.get_logger(__name__)

_ENTRY_POINT_GROUP = "marlowe.attacks"


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, BaseAttackPlugin] = {}

    def discover(self) -> None:
        """
        Load all plugins registered under the marlowe.attacks entry point group.

        Failed plugins are skipped with a warning so one broken plugin does not
        prevent the others from loading.
        """
        eps = entry_points(group=_ENTRY_POINT_GROUP)
        for ep in eps:
            try:
                cls = ep.load()
                instance = cls()
                self._plugins[instance.plugin_id] = instance
                log.debug("plugin loaded", plugin=instance.plugin_id)
            except Exception as exc:
                log.warning("plugin load failed, skipping", name=ep.name, error=str(exc))
        log.info("plugins discovered", count=len(self._plugins))

    def register(self, plugin: BaseAttackPlugin) -> None:
        """
        Manually register a plugin.

        Useful for tests and custom integrations. Logs a warning if a plugin
        with the same ID is already registered, as the previous one will be replaced.
        """
        if plugin.plugin_id in self._plugins:
            log.warning("overriding existing plugin", plugin_id=plugin.plugin_id)
        self._plugins[plugin.plugin_id] = plugin

    def get(self, plugin_id: str) -> BaseAttackPlugin:
        """Return the plugin with the given ID, or raise PluginNotFoundError."""
        if plugin_id not in self._plugins:
            raise PluginNotFoundError(
                f"Plugin '{plugin_id}' not found. Available: {self.all_ids()}"
            )
        return self._plugins[plugin_id]

    def all_ids(self) -> list[str]:
        """Return the IDs of all registered plugins."""
        return list(self._plugins.keys())

    def all_plugins(self) -> list[BaseAttackPlugin]:
        """Return all registered plugin instances."""
        return list(self._plugins.values())

    def __len__(self) -> int:
        return len(self._plugins)
