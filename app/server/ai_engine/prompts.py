"""
ARGOS — AI Engine Prompts
System prompt and user prompt builder for threat analysis.
"""
from __future__ import annotations

import json

SYSTEM_PROMPT = """You are ARGOS, an autonomous cybersecurity AI analyst.
Analyze the threat event described and respond with a JSON object containing exactly these fields:
- severity_confirmed: boolean — does the data confirm the reported severity?
- action: string — one of: block_ip, deploy_honeypot, isolate_process, close_port, alert_human, monitor
- reasoning: string — brief explanation, max 2 sentences
- confidence: float 0.0-1.0 — your confidence in this assessment
- escalate_to_human: boolean — should a human review this?

Action selection guide:
- block_ip: confirmed attacker, high confidence, brute force or repeat offender
- deploy_honeypot: port scan detected, gather attacker intelligence
- isolate_process: confirmed malware process running
- close_port: vulnerable port actively being exploited
- alert_human: ambiguous situation, novel attack, or low confidence
- monitor: low-risk anomaly, needs observation not action

Respond ONLY with valid JSON. No markdown, no explanation outside the JSON."""


def build_threat_prompt(event: dict) -> str:
    """Build structured threat description for AI analysis."""
    lines = [
        f"Threat Type: {event.get('threat_type', 'unknown')}",
        f"Severity: {event.get('severity', 'unknown')}",
        f"Source IP: {event.get('source_ip', 'unknown')}",
        f"Target Port: {event.get('target_port', 0)}",
        f"Protocol: {event.get('protocol', 'tcp')}",
        f"Description: {event.get('description', '')}",
        f"Raw Data: {json.dumps(event.get('raw_data', {}), indent=2)}",
    ]
    # Add historical context if available
    if event.get('device_platform'):
        lines.append(f"Device Platform: {event['device_platform']}")
    if event.get('history_count'):
        lines.append(f"Previous incidents from this IP: {event['history_count']}")
    return "\n".join(lines)


def build_training_pair(event: dict, decision: dict) -> tuple[str, str]:
    """Build instruction-tuning pair for LoRA training."""
    prompt = build_threat_prompt(event)
    completion = json.dumps({
        "severity_confirmed": decision.get("severity_confirmed", True),
        "action": decision["action"],
        "reasoning": decision["reasoning"],
        "confidence": decision["confidence"],
        "escalate_to_human": decision.get("escalate_to_human", False),
    })
    return prompt, completion
