"""
ARGOS — Rule-Based Fallback Engine
Deterministic rule engine used when Ollama is unavailable.
"""
from __future__ import annotations

RULE_ENGINE: dict[str, dict] = {
    "port_scan": {
        "action": "deploy_honeypot",
        "confidence": 0.92,
        "escalate_to_human": False,
        "reasoning": "Port scan detected — deploying honeypot to gather attacker TTPs.",
    },
    "brute_force": {
        "action": "block_ip",
        "confidence": 0.97,
        "escalate_to_human": False,
        "reasoning": "Brute force authentication attack — blocking IP immediately.",
    },
    "repeat_offender": {
        "action": "block_ip",
        "confidence": 0.99,
        "escalate_to_human": False,
        "reasoning": "Known malicious IP with prior incident history — blocking immediately.",
    },
    "suspicious_process": {
        "action": "isolate_process",
        "confidence": 0.85,
        "escalate_to_human": True,
        "reasoning": "Process matches known malware pattern — suspending and alerting human.",
    },
    "high_cpu_process": {
        "action": "alert_human",
        "confidence": 0.60,
        "escalate_to_human": True,
        "reasoning": "Unusual CPU usage pattern — possible cryptominer, needs human verification.",
    },
    "ddos": {
        "action": "block_ip",
        "confidence": 0.95,
        "escalate_to_human": False,
        "reasoning": "DDoS traffic pattern detected — blocking source IP.",
    },
    "ransomware": {
        "action": "isolate_process",
        "confidence": 0.98,
        "escalate_to_human": True,
        "reasoning": "Ransomware activity detected — isolating process and alerting human immediately.",
    },
    "cryptominer": {
        "action": "isolate_process",
        "confidence": 0.90,
        "escalate_to_human": True,
        "reasoning": "Cryptominer detected — suspending process and alerting human.",
    },
    "exfiltration": {
        "action": "alert_human",
        "confidence": 0.70,
        "escalate_to_human": True,
        "reasoning": "Possible data exfiltration — alerting human for investigation.",
    },
    "c2_beacon": {
        "action": "block_ip",
        "confidence": 0.88,
        "escalate_to_human": True,
        "reasoning": "C2 beacon pattern detected — blocking IP and alerting human.",
    },
    "lateral_movement": {
        "action": "alert_human",
        "confidence": 0.75,
        "escalate_to_human": True,
        "reasoning": "Lateral movement detected — alerting human for investigation.",
    },
}

_DEFAULT_RULE: dict = {
    "action": "alert_human",
    "confidence": 0.5,
    "escalate_to_human": True,
    "reasoning": "Unknown threat type — escalating to human review.",
}


class RuleBasedEngine:
    """Deterministic rule engine used as Layer 2 fallback when Ollama is unavailable."""

    def analyze(self, event: dict) -> dict:
        """
        Match the event's threat_type against the rule table and return a
        standardised response dict (same schema as the AI JSON output).
        """
        threat_type = event.get("threat_type", "anomaly")
        result = RULE_ENGINE.get(threat_type, _DEFAULT_RULE).copy()
        result["severity_confirmed"] = event.get("severity") in ("high", "critical")
        return result
