"""
ARGOS — Session Hooks
Adapted from Claude Code utils/hooks/sessionHooks.ts (Anthropic Inc.)

Session-scoped, in-memory function hooks — temporary callbacks that run
during a session and are cleared when the session ends.

Unlike post-sampling hooks (which fire after each complete turn), session
hooks fire at specific events during tool execution and can BLOCK an action
by returning False. Used for security policy enforcement.

Hook events:
  pre_tool_use    — fires before a tool executes; return False to deny
  post_tool_use   — fires after a tool executes (informational)
  pre_analysis    — fires before threat analysis starts
  post_analysis   — fires after threat analysis completes

Usage:
    from .session_hooks import SessionHookRegistry

    registry = SessionHookRegistry(session_id="session-abc")

    # Block bash commands that contain "curl" (example policy)
    def no_curl(tool_name, args, **_):
        if tool_name == "bash" and "curl" in args.get("command", ""):
            return False   # BLOCK
        return True        # ALLOW

    registry.add("pre_tool_use", no_curl, error_message="curl blocked by policy")

    # Check before every tool call:
    allowed, msg = await registry.run("pre_tool_use", tool_name="bash", args={...})
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Literal, Optional

log = logging.getLogger("argos.session_hooks")

# ─── TYPES ────────────────────────────────────────────────────────────────────

HookEvent = Literal["pre_tool_use", "post_tool_use", "pre_analysis", "post_analysis"]

# Callback signature: receives event kwargs, returns True (allow) or False (block)
HookCallback = Callable[..., bool | Awaitable[bool]]


@dataclass
class FunctionHook:
    id:            str
    callback:      HookCallback
    error_message: str
    timeout_s:     float = 5.0


# ─── REGISTRY ─────────────────────────────────────────────────────────────────

class SessionHookRegistry:
    """
    Per-session in-memory hook registry.
    Thread-safe for concurrent asyncio tasks (single-threaded event loop).
    """

    def __init__(self, session_id: str = "") -> None:
        self.session_id = session_id
        # event → list of hooks
        self._hooks: dict[HookEvent, list[FunctionHook]] = {}

    def add(
        self,
        event:         HookEvent,
        callback:      HookCallback,
        error_message: str = "Action blocked by session hook",
        timeout_s:     float = 5.0,
        hook_id:       Optional[str] = None,
    ) -> str:
        """
        Register a function hook for an event.
        Returns the hook ID (use to remove it later).
        Same as Claude Code's addFunctionHook().
        """
        hid  = hook_id or str(uuid.uuid4())
        hook = FunctionHook(id=hid, callback=callback, error_message=error_message, timeout_s=timeout_s)
        self._hooks.setdefault(event, []).append(hook)
        log.debug("[SessionHooks] Added hook '%s' for %s", hid, event)
        return hid

    def remove(self, hook_id: str) -> None:
        """Remove a hook by ID across all events."""
        for event in list(self._hooks):
            before = len(self._hooks[event])
            self._hooks[event] = [h for h in self._hooks[event] if h.id != hook_id]
            if not self._hooks[event]:
                del self._hooks[event]
            if len(self._hooks.get(event, [])) < before:
                log.debug("[SessionHooks] Removed hook '%s'", hook_id)
                return

    def clear(self) -> None:
        """Clear all hooks (call on session end)."""
        self._hooks.clear()
        log.debug("[SessionHooks] Cleared all hooks for session %s", self.session_id)

    async def run(self, event: HookEvent, **kwargs: Any) -> tuple[bool, Optional[str]]:
        """
        Run all hooks for an event.
        Returns (True, None) if all pass, or (False, error_message) on first denial.

        kwargs are passed to every callback — use consistent keys per event:
          pre_tool_use:  tool_name=str, args=dict
          post_tool_use: tool_name=str, args=dict, result=str
          pre_analysis:  event=dict
          post_analysis: event=dict, decision=dict
        """
        for hook in self._hooks.get(event, []):
            try:
                result = hook.callback(**kwargs)
                if asyncio.iscoroutine(result):
                    result = await asyncio.wait_for(result, timeout=hook.timeout_s)
                if result is False:
                    log.info("[SessionHooks] Hook '%s' denied %s", hook.id, event)
                    return False, hook.error_message
            except asyncio.TimeoutError:
                log.warning("[SessionHooks] Hook '%s' timed out after %.1fs", hook.id, hook.timeout_s)
                # Timeout = allow (fail open) to avoid blocking the engine
            except Exception as exc:
                log.warning("[SessionHooks] Hook '%s' error: %s — failing open", hook.id, exc)
        return True, None

    def __len__(self) -> int:
        return sum(len(v) for v in self._hooks.values())
