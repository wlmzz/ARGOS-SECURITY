from .network import TOOLS as NETWORK_TOOLS
from .osint import TOOLS as OSINT_TOOLS
from .analysis import TOOLS as ANALYSIS_TOOLS
from .vuln import TOOLS as VULN_TOOLS
from .osint_advanced import TOOLS as OSINT_ADV_TOOLS
from .attribution import TOOLS as ATTRIBUTION_TOOLS
from .hardening import TOOLS as HARDENING_TOOLS
from .honeypot import TOOLS as HONEYPOT_TOOLS

ALL_TOOLS: dict = {}
ALL_TOOLS.update(NETWORK_TOOLS)
ALL_TOOLS.update(OSINT_TOOLS)
ALL_TOOLS.update(OSINT_ADV_TOOLS)
ALL_TOOLS.update(ANALYSIS_TOOLS)
ALL_TOOLS.update(VULN_TOOLS)
ALL_TOOLS.update(ATTRIBUTION_TOOLS)
ALL_TOOLS.update(HARDENING_TOOLS)
ALL_TOOLS.update(HONEYPOT_TOOLS)

# Subagent orchestration + plugin loader
import sys, os as _os
_agent_dir = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _agent_dir not in sys.path:
    sys.path.insert(0, _agent_dir)

try:
    from orchestrator import TOOLS as ORCHESTRATOR_TOOLS
    ALL_TOOLS.update(ORCHESTRATOR_TOOLS)
except Exception as _e:
    import logging
    logging.getLogger("argos.tools").warning("Orchestrator load error: %s", _e)

try:
    from plugin_loader import load_plugins, get_all_plugin_tools
    load_plugins()
    ALL_TOOLS.update(get_all_plugin_tools())
except Exception as _e:
    import logging
    logging.getLogger("argos.tools").warning("Plugin loader error: %s", _e)
