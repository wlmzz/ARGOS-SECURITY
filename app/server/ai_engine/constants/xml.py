"""
ARGOS — XML Tag Constants
Adapted from Claude Code constants/xml.ts (Anthropic Inc.)

Single source of truth for all XML tags used in messages between
Seneca and tool results. Keeps string literals out of scattered code.

Tags the model already understands from Claude Code training:
  <persisted-output>     — large tool result saved to disk
  <compact-context>      — compacted conversation summary
  <task-notification>    — coordinator worker result

ARGOS-specific additions:
  <threat-event>         — incoming threat event wrapper
  <analysis-result>      — Seneca's final JSON decision
"""

# ─── TOOL RESULT PERSISTENCE (from toolResultStorage.ts) ─────────────────────

PERSISTED_OUTPUT_TAG         = "persisted-output"
PERSISTED_OUTPUT_OPEN        = f"<{PERSISTED_OUTPUT_TAG}>"
PERSISTED_OUTPUT_CLOSE       = f"</{PERSISTED_OUTPUT_TAG}>"

# Inserted by compaction to mark summarized history
COMPACT_CONTEXT_TAG          = "compact-context"
COMPACT_CONTEXT_OPEN         = f"<{COMPACT_CONTEXT_TAG}>"
COMPACT_CONTEXT_CLOSE        = f"</{COMPACT_CONTEXT_TAG}>"

# ─── COORDINATOR / TASK NOTIFICATIONS (from xml.ts) ──────────────────────────

TASK_NOTIFICATION_TAG        = "task-notification"
TASK_ID_TAG                  = "task-id"
TOOL_USE_ID_TAG              = "tool-use-id"
TASK_TYPE_TAG                = "task-type"
OUTPUT_FILE_TAG              = "output-file"
STATUS_TAG                   = "status"
SUMMARY_TAG                  = "summary"
REASON_TAG                   = "reason"

# ─── BASH TOOL I/O (from xml.ts) ─────────────────────────────────────────────

BASH_INPUT_TAG               = "bash-input"
BASH_STDOUT_TAG              = "bash-stdout"
BASH_STDERR_TAG              = "bash-stderr"

# ─── ARGOS-SPECIFIC ───────────────────────────────────────────────────────────

# Wraps an incoming threat event in the analysis prompt
THREAT_EVENT_TAG             = "threat-event"
THREAT_EVENT_OPEN            = f"<{THREAT_EVENT_TAG}>"
THREAT_EVENT_CLOSE           = f"</{THREAT_EVENT_TAG}>"

# Wraps Seneca's final JSON decision
ANALYSIS_RESULT_TAG          = "analysis-result"
ANALYSIS_RESULT_OPEN         = f"<{ANALYSIS_RESULT_TAG}>"
ANALYSIS_RESULT_CLOSE        = f"</{ANALYSIS_RESULT_TAG}>"

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def wrap(tag: str, content: str) -> str:
    """Wrap content in an XML tag: <tag>content</tag>."""
    return f"<{tag}>\n{content}\n</{tag}>"


def extract(tag: str, text: str) -> str | None:
    """Extract the first occurrence of <tag>...</tag> content, or None."""
    import re
    m = re.search(rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", text, re.DOTALL)
    return m.group(1).strip() if m else None
