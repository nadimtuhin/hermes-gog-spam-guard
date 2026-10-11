"""
Hermes Agent Plugin Adapter for gog-spam-guard.
Provides sandboxed spam scanning, injection quarantine, and safe server-side filter creation tools.
"""

import json
from .detector import process_spam_batch
from .validator import validate_gmail_query, execute_safe_filter_create
from .cluster import cluster_spam_messages


def register(ctx):
    """Register Hermes tools and pre-execution safety hooks."""
    ctx.register_tool(
        name="gog_spam_scan",
        description="Safely scan Gmail spam via gog CLI, sanitize prompts, and quarantine injection payloads.",
        parameters={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max emails to fetch (default 50)", "default": 50},
                "client": {"type": "string", "description": "Optional gog client name"}
            }
        },
        handler=_tool_gog_spam_scan
    )

    ctx.register_tool(
        name="gog_filter_apply",
        description="Safely validate and apply a server-side Gmail trash or allowlist filter via gog CLI.",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Gmail search query to filter"},
                "action": {"type": "string", "enum": ["--trash", "--never-spam", "--archive", "--mark-read"], "default": "--trash"},
                "client": {"type": "string", "description": "Optional gog client name"}
            },
            "required": ["query"]
        },
        handler=_tool_gog_filter_apply
    )


def _tool_gog_spam_scan(args, **_kwargs):
    """Hermes tool handler for scanning spam safely."""
    import subprocess
    limit = args.get("limit", 50)
    client = args.get("client")

    cmd = ["gog"]
    if client:
        cmd.extend(["--client", client])
    cmd.extend(["gmail", "search", "in:spam", f"--limit={limit}", "-j", "--results-only"])

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        raw_emails = json.loads(res.stdout)
    except Exception as e:
        return json.dumps({"success": False, "error": f"Failed to fetch from gog: {str(e)}"})

    processed = process_spam_batch(raw_emails)
    clusters = cluster_spam_messages(processed["safe_emails"])

    return json.dumps({
        "success": True,
        "total": len(raw_emails),
        "safe_count": processed["safe_count"],
        "quarantined_count": processed["quarantined_count"],
        "quarantined": processed["quarantined"],
        "clusters": {k: len(v) for k, v in clusters.items() if v},
        "recommended_allowlist": [
            {"sender": m["sender"], "subject": m["subject"]} for m in clusters["recommended_allowlist"]
        ]
    }, indent=2)


def _tool_gog_filter_apply(args, **_kwargs):
    """Hermes tool handler for applying filters safely."""
    query = args.get("query", "")
    action = args.get("action", "--trash")
    client = args.get("client")

    valid, reason = validate_gmail_query(query)
    if not valid:
        return json.dumps({"success": False, "error": f"Filter query rejected by safety validator: {reason}"})

    res = execute_safe_filter_create(query, action, client)
    return json.dumps(res)
