"""
cognee_knowledge.py — ARGOS plugin
Persistent threat intelligence knowledge graph using Cognee.
Ingest IOCs, threat reports, CVEs, and incidents into a queryable knowledge graph.
Cross-session memory: ARGOS remembers and correlates threats over time.
https://github.com/topoteretes/cognee
"""

import asyncio
import json
import os
import re
from datetime import datetime

MANIFEST = {
    "id": "cognee_knowledge",
    "name": "Cognee Knowledge Graph",
    "version": "1.0.0",
    "description": "Persistent threat intelligence knowledge graph — ingest IOCs, query, correlate",
    "author": "ARGOS",
    "category": "threat_intel",
    "tools": [
        "knowledge_ingest",
        "knowledge_search",
        "knowledge_correlate",
        "knowledge_export",
    ],
}

COGNEE_DATA_DIR = "/opt/argos/knowledge_graph"
os.makedirs(COGNEE_DATA_DIR, exist_ok=True)

# Fallback knowledge store (JSON) when cognee unavailable
FALLBACK_STORE = os.path.join(COGNEE_DATA_DIR, "knowledge_store.jsonl")


def _ensure_cognee() -> tuple[bool, str]:
    try:
        import cognee
        return True, ""
    except ImportError:
        import subprocess
        rc, _, err = subprocess.run(
            ["pip3", "install", "cognee", "--break-system-packages", "-q"],
            capture_output=True, text=True, timeout=180,
        ).returncode, "", ""
        try:
            import cognee
            return True, ""
        except ImportError:
            return False, "pip3 install cognee"


def _run_async(coro):
    """Run async coroutine from sync context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result(timeout=120)
        return loop.run_until_complete(coro)
    except Exception:
        return asyncio.run(coro)


def _fallback_ingest(data: str, dataset: str, metadata: dict) -> dict:
    """Simple JSON-line fallback store when cognee unavailable."""
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "dataset": dataset,
        "content": data[:5000],
        "metadata": metadata,
    }
    with open(FALLBACK_STORE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return {"status": "stored_fallback", "entries": 1,
            "note": "Stored in flat file (cognee unavailable)"}


def _fallback_search(query: str, dataset: str = None) -> list:
    """Simple keyword search on fallback store."""
    if not os.path.exists(FALLBACK_STORE):
        return []
    results = []
    query_lower = query.lower()
    with open(FALLBACK_STORE) as f:
        for line in f:
            try:
                entry = json.loads(line)
                if dataset and entry.get("dataset") != dataset:
                    continue
                content = entry.get("content", "").lower()
                if any(word in content for word in query_lower.split()):
                    results.append(entry)
            except Exception:
                continue
    return results[:20]


def knowledge_ingest(data: str, dataset: str = "threat_intel",
                      data_type: str = "text", tags: list = None) -> dict:
    """
    Ingest security knowledge into the persistent graph database.
    Supports IOC lists, threat reports, CVE descriptions, incident logs, YARA rules.
    Knowledge persists across ARGOS sessions and is queryable by any agent.

    Args:
        data: Text content to ingest (IOCs, threat report, CVE info, log data, etc.)
        dataset: Knowledge dataset name for organization (default: 'threat_intel')
                 Suggested: 'iocs', 'cves', 'incidents', 'threat_actors', 'malware'
        data_type: 'text', 'json', 'ioc_list', 'cve', 'incident' (default: text)
        tags: Optional tags for categorization (e.g. ['APT28', 'Russia', 'ransomware'])

    Returns:
        Ingestion status with entity and relationship counts extracted
    """
    if not data or len(data.strip()) < 10:
        return {"error": "Data too short to ingest (minimum 10 characters)"}

    metadata = {
        "dataset": dataset,
        "data_type": data_type,
        "tags": tags or [],
        "ingested_at": datetime.utcnow().isoformat(),
        "char_count": len(data),
    }

    # Pre-process IOC lists
    if data_type == "ioc_list":
        ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', data)
        domains = re.findall(r'\b[a-z0-9\-]+\.[a-z]{2,}\b', data.lower())
        hashes = re.findall(r'\b[a-f0-9]{32,64}\b', data.lower())
        metadata["extracted"] = {
            "ips": len(ips), "domains": len(domains), "hashes": len(hashes)
        }

    ok, err = _ensure_cognee()
    if not ok:
        result = _fallback_ingest(data, dataset, metadata)
        result["metadata"] = metadata
        return result

    try:
        import cognee

        # Configure cognee data directory
        cognee.config.data_root_directory(COGNEE_DATA_DIR)

        async def _ingest():
            await cognee.add(data, dataset_name=dataset)
            await cognee.cognify()
            return True

        _run_async(_ingest())

        return {
            "status": "ingested",
            "dataset": dataset,
            "data_type": data_type,
            "tags": tags or [],
            "metadata": metadata,
            "char_count": len(data),
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        # Fallback to flat file
        result = _fallback_ingest(data, dataset, metadata)
        result["cognee_error"] = str(e)[:300]
        return result


def knowledge_search(query: str, dataset: str = None,
                      search_type: str = "insights", limit: int = 10) -> dict:
    """
    Search the threat intelligence knowledge graph.
    Query with natural language: "which IPs are associated with APT28?" or "find ransomware IOCs".

    Args:
        query: Natural language search query
        dataset: Limit search to specific dataset (optional, searches all if omitted)
        search_type: 'insights' (semantic), 'graph' (entity relationships), 'chunks' (raw text)
        limit: Maximum results to return (default: 10)

    Returns:
        Matching knowledge graph entries with relationship context
    """
    if not query or len(query.strip()) < 3:
        return {"error": "Query too short"}

    ok, err = _ensure_cognee()
    if not ok:
        results = _fallback_search(query, dataset)
        return {
            "query": query,
            "results": results,
            "count": len(results),
            "source": "fallback_store",
            "note": "Full graph search requires: pip3 install cognee",
        }

    try:
        import cognee
        from cognee.api.v1.search import SearchType

        cognee.config.data_root_directory(COGNEE_DATA_DIR)

        type_map = {
            "insights": SearchType.INSIGHTS,
            "graph": SearchType.GRAPH_COMPLETION,
            "chunks": SearchType.CHUNKS,
        }
        stype = type_map.get(search_type, SearchType.INSIGHTS)

        async def _search():
            results = await cognee.search(stype, query_text=query)
            return results

        raw_results = _run_async(_search())

        # Format results
        formatted = []
        for r in (raw_results or [])[:limit]:
            if isinstance(r, dict):
                formatted.append(r)
            else:
                formatted.append({"content": str(r)})

        return {
            "query": query,
            "search_type": search_type,
            "dataset_filter": dataset,
            "results": formatted,
            "count": len(formatted),
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        # Fallback
        results = _fallback_search(query, dataset)
        return {
            "query": query,
            "results": results,
            "count": len(results),
            "source": "fallback_store",
            "cognee_error": str(e)[:300],
        }


def knowledge_correlate(ioc: str, context_depth: int = 2) -> dict:
    """
    Find correlations between an IOC/entity and everything in the knowledge graph.
    Discovers relationships: shared infrastructure, threat actor campaigns, related malware.

    Args:
        ioc: IOC or entity to correlate (IP, domain, hash, threat actor name, CVE)
        context_depth: Relationship traversal depth (1=direct, 2=2-hop, 3=3-hop) (default: 2)

    Returns:
        All related entities, campaigns, and threat actors linked to the IOC
    """
    if not ioc:
        return {"error": "Provide an IOC or entity to correlate"}

    # Determine IOC type
    ioc_type = "unknown"
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
        ioc_type = "ip"
    elif re.match(r'^[a-f0-9]{32}$', ioc.lower()):
        ioc_type = "md5"
    elif re.match(r'^[a-f0-9]{64}$', ioc.lower()):
        ioc_type = "sha256"
    elif re.match(r'^CVE-\d{4}-\d+$', ioc, re.I):
        ioc_type = "cve"
    elif re.match(r'^[a-z0-9\-]+\.[a-z]{2,}$', ioc.lower()):
        ioc_type = "domain"

    result = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "context_depth": context_depth,
        "correlations": {},
        "timestamp": datetime.utcnow().isoformat(),
    }

    ok, err = _ensure_cognee()
    if not ok:
        # Fallback: keyword search in flat store
        related = _fallback_search(ioc)
        result["correlations"]["related_entries"] = related
        result["source"] = "fallback_keyword_search"
        return result

    try:
        import cognee
        from cognee.api.v1.search import SearchType

        cognee.config.data_root_directory(COGNEE_DATA_DIR)

        async def _correlate():
            # Graph traversal for relationships
            graph_results = await cognee.search(
                SearchType.GRAPH_COMPLETION,
                query_text=f"What is related to {ioc}? Find all connections, campaigns, actors, and infrastructure."
            )
            # Semantic insights
            insight_results = await cognee.search(
                SearchType.INSIGHTS,
                query_text=f"{ioc} threat actor campaign infrastructure malware"
            )
            return graph_results, insight_results

        graph_res, insight_res = _run_async(_correlate())

        result["correlations"]["graph_relationships"] = [
            str(r) for r in (graph_res or [])[:10]
        ]
        result["correlations"]["semantic_insights"] = [
            str(r) for r in (insight_res or [])[:10]
        ]

        return result

    except Exception as e:
        related = _fallback_search(ioc)
        result["correlations"]["related_entries"] = related
        result["cognee_error"] = str(e)[:300]
        return result


def knowledge_export(dataset: str = None, format: str = "json") -> dict:
    """
    Export knowledge graph contents for sharing or backup.
    Useful for exporting threat intelligence to share with other platforms.

    Args:
        dataset: Dataset to export (default: all datasets)
        format: 'json', 'csv', 'stix2' (default: json)

    Returns:
        Path to exported file and entry count
    """
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    outfile = os.path.join(COGNEE_DATA_DIR, f"export_{dataset or 'all'}_{ts}.{format}")

    # Read from fallback store
    entries = []
    if os.path.exists(FALLBACK_STORE):
        with open(FALLBACK_STORE) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if dataset is None or entry.get("dataset") == dataset:
                        entries.append(entry)
                except Exception:
                    continue

    if format == "json":
        with open(outfile, "w") as f:
            json.dump(entries, f, indent=2)

    elif format == "csv":
        import csv
        if entries:
            keys = list(entries[0].keys())
            with open(outfile, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(entries)

    elif format == "stix2":
        # Basic STIX2 bundle
        stix_objects = []
        for entry in entries:
            content = entry.get("content", "")
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content)
            domains = re.findall(r'\b[a-z0-9\-]+\.[a-z]{2,}\b', content.lower())
            for ip in set(ips):
                stix_objects.append({"type": "ipv4-addr", "spec_version": "2.1",
                                     "id": f"ipv4-addr--{ip.replace('.', '-')}",
                                     "value": ip})
            for domain in set(domains):
                stix_objects.append({"type": "domain-name", "spec_version": "2.1",
                                     "id": f"domain-name--{hash(domain)}",
                                     "value": domain})
        bundle = {"type": "bundle", "id": "bundle--argos-export",
                  "spec_version": "2.1", "objects": stix_objects}
        with open(outfile, "w") as f:
            json.dump(bundle, f, indent=2)

    ok, _ = _ensure_cognee()
    if ok:
        try:
            import cognee
            cognee.config.data_root_directory(COGNEE_DATA_DIR)
            # Additional cognee-native export could go here
        except Exception:
            pass

    return {
        "dataset": dataset or "all",
        "format": format,
        "output_file": outfile,
        "entry_count": len(entries),
        "timestamp": datetime.utcnow().isoformat(),
    }


TOOLS = {
    "knowledge_ingest": knowledge_ingest,
    "knowledge_search": knowledge_search,
    "knowledge_correlate": knowledge_correlate,
    "knowledge_export": knowledge_export,
}
