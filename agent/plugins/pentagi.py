"""
ARGOS Plugin: PentAGI
Multi-agent autonomous penetration testing platform (Go backend + REST/GraphQL API).
Runs a team of AI agents (Orchestrator, Researcher, Developer, Executor) with 20+ built-in
security tools (nmap, metasploit, sqlmap, etc.) and a knowledge graph of findings.

Deploy (Docker Compose):
  git clone https://github.com/vxcontrol/pentagi
  cp .env.example .env   # set LLM keys (OpenAI, Anthropic, Ollama, etc.)
  docker compose up -d
  # Web UI: https://localhost:8443
  # API docs: https://localhost:8443/api/v1/swagger/index.html

Set env vars:
  PENTAGI_URL    = https://your-pentagi-host:8443
  PENTAGI_TOKEN  = your-bearer-token (created in Settings → API Tokens)

Repo: https://github.com/vxcontrol/pentagi
"""
from __future__ import annotations
import json, os, ssl, time, urllib.request, urllib.error

MANIFEST = {
    "id":          "pentagi",
    "name":        "PentAGI",
    "description": "Autonomous AI pentest platform: multi-agent team + 20 security tools + knowledge graph. REST/GraphQL API integration.",
    "version":     "1.0.0",
    "author":      "ARGOS",
    "requires":    [],
}

# PentAGI uses a self-signed cert by default → skip SSL verification
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE


def _pentagi_request(method: str, path: str, body: dict | None = None) -> dict:
    base  = os.getenv("PENTAGI_URL", "").rstrip("/")
    token = os.getenv("PENTAGI_TOKEN", "")

    if not base:
        return {"error": "PENTAGI_URL not set (e.g. https://your-pentagi:8443)"}
    if not token:
        return {"error": "PENTAGI_TOKEN not set (create in PentAGI web UI → Settings → API Tokens)"}

    url  = f"{base}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
        "User-Agent":    "ARGOS/1.0",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30, context=_SSL_CTX) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode(errors="replace")
        try:
            return json.loads(body_txt)
        except Exception:
            return {"error": f"HTTP {e.code}: {body_txt[:300]}"}
    except Exception as e:
        return {"error": str(e)}


def _gql(query: str, variables: dict | None = None) -> dict:
    base  = os.getenv("PENTAGI_URL", "").rstrip("/")
    token = os.getenv("PENTAGI_TOKEN", "")

    if not base:
        return {"error": "PENTAGI_URL not set"}
    if not token:
        return {"error": "PENTAGI_TOKEN not set"}

    payload = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request(
        f"{base}/api/v1/graphql",
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
            "User-Agent":    "ARGOS/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30, context=_SSL_CTX) as r:
            result = json.loads(r.read().decode())
            if "errors" in result:
                return {"error": str(result["errors"][0].get("message", result["errors"]))}
            return result.get("data", {})
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            return json.loads(body)
        except Exception:
            return {"error": f"HTTP {e.code}: {body[:300]}"}
    except Exception as e:
        return {"error": str(e)}


def pentagi_start_flow(target: str, instructions: str = "",
                       model_provider: str = "anthropic",
                       wait: bool = True, poll_timeout: int = 600) -> dict:
    """Start a PentAGI autonomous penetration test flow against a target.
    ⚠️  AUTHORIZED PENETRATION TESTING ONLY.

    target: IP, domain, URL, or natural language description of the target
    instructions: optional additional guidance for the AI agents
    model_provider: LLM backend ('anthropic', 'openai', 'ollama', 'local')
    wait: if True, poll until flow completes (up to poll_timeout seconds)
    """
    mutation = """
    mutation CreateFlow($input: FlowInput!) {
      createFlow(input: $input) {
        id
        title
        status
        created_at
      }
    }
    """
    task = target
    if instructions:
        task += f"\n\nAdditional instructions: {instructions}"

    result = _gql(mutation, {"input": {"task": task, "model_provider": model_provider}})
    if "error" in result:
        return result

    flow = result.get("createFlow", {})
    flow_id = flow.get("id", "")

    if not flow_id:
        return {"error": "Failed to create flow — no ID returned", "raw": result}

    base_response = {
        "target":      target,
        "source":      "PentAGI",
        "flow_id":     flow_id,
        "title":       flow.get("title", ""),
        "status":      flow.get("status", ""),
        "created_at":  flow.get("created_at", ""),
    }

    if not wait:
        base_response["message"] = f"Flow started. Use pentagi_get_flow(flow_id='{flow_id}') to check progress."
        return base_response

    # Poll for completion
    start = time.time()
    while time.time() - start < poll_timeout:
        status_result = pentagi_get_flow(flow_id)
        if "error" in status_result:
            return {**base_response, "error": status_result["error"]}

        current_status = status_result.get("status", "")
        if current_status in ("completed", "failed", "stopped"):
            return status_result

        time.sleep(15)

    # Timeout — return partial
    return {
        **base_response,
        "status":  "running",
        "message": f"Flow still running after {poll_timeout}s. Use pentagi_get_flow(flow_id='{flow_id}') to check.",
    }


def pentagi_get_flow(flow_id: str) -> dict:
    """Get the status and results of a PentAGI pentest flow."""
    query = """
    query GetFlow($id: ID!) {
      flow(id: $id) {
        id
        title
        status
        created_at
        updated_at
        result
        subtasks {
          edges {
            node {
              id
              title
              status
              result
              tool_calls {
                edges {
                  node {
                    tool_name
                    input
                    output
                    status
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    result = _gql(query, {"id": flow_id})
    if "error" in result:
        return result

    flow = result.get("flow", {})
    if not flow:
        return {"error": f"Flow '{flow_id}' not found"}

    subtasks = []
    for edge in flow.get("subtasks", {}).get("edges", []):
        node = edge.get("node", {})
        tool_calls = [
            {
                "tool":   tc["node"]["tool_name"],
                "input":  str(tc["node"]["input"])[:200],
                "output": str(tc["node"]["output"])[:300],
                "status": tc["node"]["status"],
            }
            for tc in (node.get("tool_calls", {}).get("edges", []) or [])[:10]
        ]
        subtasks.append({
            "id":         node.get("id"),
            "title":      node.get("title"),
            "status":     node.get("status"),
            "result":     (node.get("result") or "")[:500],
            "tool_calls": tool_calls,
        })

    return {
        "flow_id":     flow_id,
        "source":      "PentAGI",
        "title":       flow.get("title", ""),
        "status":      flow.get("status", ""),
        "created_at":  flow.get("created_at", ""),
        "updated_at":  flow.get("updated_at", ""),
        "result":      (flow.get("result") or "")[:3000],
        "subtask_count": len(subtasks),
        "subtasks":    subtasks,
    }


def pentagi_list_flows(limit: int = 10) -> dict:
    """List recent PentAGI pentest flows with their status."""
    query = """
    query ListFlows($first: Int) {
      flows(first: $first, orderBy: {field: CREATED_AT, direction: DESC}) {
        edges {
          node {
            id
            title
            status
            created_at
            updated_at
          }
        }
        pageInfo { totalCount }
      }
    }
    """
    result = _gql(query, {"first": min(limit, 50)})
    if "error" in result:
        return result

    flows_data = result.get("flows", {})
    flows = [
        {
            "id":         e["node"]["id"],
            "title":      e["node"]["title"],
            "status":     e["node"]["status"],
            "created_at": e["node"]["created_at"],
            "updated_at": e["node"]["updated_at"],
        }
        for e in flows_data.get("edges", [])
    ]

    return {
        "source":      "PentAGI",
        "total_count": flows_data.get("pageInfo", {}).get("totalCount", 0),
        "flows":       flows,
    }


TOOLS = {
    "pentagi_start_flow": {
        "fn": pentagi_start_flow,
        "description": (
            "Start a PentAGI autonomous penetration test against a target. "
            "Spawns a team of AI agents (Orchestrator, Researcher, Developer, Executor) "
            "with 20+ built-in tools (nmap, metasploit, sqlmap, etc.). "
            "Returns findings, tool calls, and a detailed result report. "
            "wait=true blocks until complete (up to poll_timeout seconds). "
            "⚠️ AUTHORIZED PENETRATION TESTING ONLY. Requires PentAGI running (PENTAGI_URL + PENTAGI_TOKEN)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target":         {"type": "string",  "description": "Target: IP, domain, URL, or description"},
                "instructions":   {"type": "string",  "description": "Additional guidance for AI agents"},
                "model_provider": {"type": "string",  "description": "LLM backend: 'anthropic', 'openai', 'ollama', 'local'"},
                "wait":           {"type": "boolean", "description": "Wait for completion (default: true)"},
                "poll_timeout":   {"type": "integer", "description": "Max seconds to wait (default: 600)"},
            },
            "required": ["target"]
        }
    },
    "pentagi_get_flow": {
        "fn": pentagi_get_flow,
        "description": "Get status and results of a PentAGI pentest flow. Returns subtask details and tool call logs.",
        "parameters": {
            "type": "object",
            "properties": {
                "flow_id": {"type": "string", "description": "Flow ID from pentagi_start_flow"}
            },
            "required": ["flow_id"]
        }
    },
    "pentagi_list_flows": {
        "fn": pentagi_list_flows,
        "description": "List recent PentAGI pentest flows with their status (running/completed/failed).",
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max flows to return (default: 10)"}
            },
            "required": []
        }
    },
}
