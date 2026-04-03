"""
ARGOS Plugin Loader — dynamic tool plugin discovery and loading.
Inspired by OpenClaw's plugin manifest + registry architecture.

Plugins live in:
  - /opt/argos/agent/plugins/          (built-in bundled plugins)
  - /opt/argos/plugins/                (user-installed plugins)
  - ARGOS_PLUGINS_DIR env var          (custom path)

Each plugin is a Python file with:
  MANIFEST = {
      "id":          "my-plugin",
      "name":        "My Plugin",
      "description": "What it does",
      "version":     "1.0.0",
      "author":      "name",
      "requires":    ["requests"],      # pip deps (optional)
  }
  TOOLS = {
      "tool_name": {"fn": fn, "description": "...", "parameters": {...}}
  }

Plugin IDs must be unique. A plugin with a duplicate ID is skipped with a warning.
Plugins that raise ImportError or lack TOOLS are silently skipped.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger("argos.plugins")

BUILTIN_PLUGINS_DIR = Path(os.path.dirname(__file__)) / "plugins"
USER_PLUGINS_DIR    = Path("/opt/argos/plugins")
CUSTOM_PLUGINS_DIR  = Path(os.getenv("ARGOS_PLUGINS_DIR", "")) if os.getenv("ARGOS_PLUGINS_DIR") else None

_loaded_plugins: dict[str, dict] = {}   # plugin_id → manifest + tools
_loaded_tool_names: set[str] = set()    # to detect collisions


def _validate_manifest(manifest: Any, path: Path) -> bool:
    if not isinstance(manifest, dict):
        log.warning("Plugin %s: MANIFEST is not a dict — skipped", path.name)
        return False
    if not manifest.get("id"):
        log.warning("Plugin %s: MANIFEST missing 'id' — skipped", path.name)
        return False
    if not re_safe_id(manifest["id"]):
        log.warning("Plugin %s: MANIFEST id '%s' contains invalid chars — skipped", path.name, manifest["id"])
        return False
    return True


def re_safe_id(s: str) -> bool:
    import re
    return bool(re.match(r"^[a-zA-Z0-9_\-]{1,64}$", s))


def _validate_tools(tools: Any, plugin_id: str) -> dict:
    if not isinstance(tools, dict):
        return {}
    valid = {}
    for name, tool_def in tools.items():
        if not isinstance(tool_def, dict):
            continue
        if not callable(tool_def.get("fn")):
            log.warning("Plugin %s: tool '%s' has no callable fn — skipped", plugin_id, name)
            continue
        if not isinstance(tool_def.get("description"), str):
            log.warning("Plugin %s: tool '%s' missing description — skipped", plugin_id, name)
            continue
        if name in _loaded_tool_names:
            log.warning("Plugin %s: tool '%s' conflicts with existing tool — skipped", plugin_id, name)
            continue
        valid[name] = tool_def
    return valid


def _load_plugin_file(path: Path) -> dict | None:
    """Load a single plugin .py file. Returns {manifest, tools} or None."""
    if path.suffix != ".py" or path.name.startswith("_"):
        return None

    spec = importlib.util.spec_from_file_location(f"argos_plugin_{path.stem}", path)
    if not spec or not spec.loader:
        return None

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        log.warning("Plugin %s: failed to load — %s", path.name, e)
        return None

    manifest = getattr(module, "MANIFEST", None)
    if not _validate_manifest(manifest, path):
        return None

    plugin_id = manifest["id"]
    if plugin_id in _loaded_plugins:
        log.warning("Plugin id '%s' already loaded — skipping %s", plugin_id, path.name)
        return None

    raw_tools = getattr(module, "TOOLS", {})
    tools = _validate_tools(raw_tools, plugin_id)

    if not tools:
        log.info("Plugin %s: no valid tools — loaded but inactive", plugin_id)

    return {"manifest": manifest, "tools": tools, "path": str(path)}


def load_plugins(extra_dirs: list[Path] | None = None) -> dict[str, dict]:
    """Discover and load all plugins. Returns dict of plugin_id → plugin_data."""
    dirs = [BUILTIN_PLUGINS_DIR, USER_PLUGINS_DIR]
    if CUSTOM_PLUGINS_DIR:
        dirs.append(CUSTOM_PLUGINS_DIR)
    if extra_dirs:
        dirs.extend(extra_dirs)

    for plugins_dir in dirs:
        if not plugins_dir.exists():
            continue
        for path in sorted(plugins_dir.glob("*.py")):
            plugin = _load_plugin_file(path)
            if not plugin:
                continue
            pid = plugin["manifest"]["id"]
            _loaded_plugins[pid] = plugin
            _loaded_tool_names.update(plugin["tools"].keys())
            log.info("Plugin loaded: %s v%s — %d tools",
                     plugin["manifest"].get("name", pid),
                     plugin["manifest"].get("version", "?"),
                     len(plugin["tools"]))

    return _loaded_plugins


def get_all_plugin_tools() -> dict[str, dict]:
    """Return merged TOOLS dict from all loaded plugins."""
    all_tools: dict[str, dict] = {}
    for plugin in _loaded_plugins.values():
        all_tools.update(plugin["tools"])
    return all_tools


def list_plugins() -> list[dict]:
    """Return metadata for all loaded plugins."""
    result = []
    for pid, plugin in _loaded_plugins.items():
        m = plugin["manifest"]
        result.append({
            "id":          pid,
            "name":        m.get("name", pid),
            "description": m.get("description", ""),
            "version":     m.get("version", "?"),
            "author":      m.get("author", ""),
            "tools":       list(plugin["tools"].keys()),
            "tool_count":  len(plugin["tools"]),
            "path":        plugin.get("path", ""),
        })
    return result


def reload_plugin(plugin_id: str) -> dict:
    """Reload a specific plugin from disk."""
    if plugin_id not in _loaded_plugins:
        return {"error": f"Plugin '{plugin_id}' not loaded"}
    plugin = _loaded_plugins[plugin_id]
    path = Path(plugin.get("path", ""))
    if not path.exists():
        return {"error": f"Plugin file not found: {path}"}
    # Remove old tools
    for tool_name in plugin["tools"]:
        _loaded_tool_names.discard(tool_name)
    del _loaded_plugins[plugin_id]
    # Reload
    new_plugin = _load_plugin_file(path)
    if not new_plugin:
        return {"error": f"Failed to reload plugin '{plugin_id}'"}
    pid = new_plugin["manifest"]["id"]
    _loaded_plugins[pid] = new_plugin
    _loaded_tool_names.update(new_plugin["tools"].keys())
    return {"status": "reloaded", "plugin_id": pid, "tools": list(new_plugin["tools"].keys())}
