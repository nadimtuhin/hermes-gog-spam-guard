"""
Gmail Filter Query Validator and Safe Non-Shell Command Builder.
"""

import subprocess
from typing import Tuple, List, Optional, Dict, Any


def validate_gmail_query(query: str) -> Tuple[bool, str]:
    """
    Validate that a Gmail filter query is safe to execute and does not contain
    shell metacharacters, syntax bombs, or dangerous wildcard patterns.
    """
    if not query or len(query.strip()) == 0:
        return False, "Query cannot be empty"

    if len(query) > 300:
        return False, "Query exceeds maximum safe length (300 chars)"

    # Strict check for shell metacharacters
    forbidden_shell_chars = [";", "`", "$", "\n", "\r", "\\", "{", "}", "<", ">"]
    for ch in forbidden_shell_chars:
        if ch in query:
            return False, f"Query contains illegal shell character: {repr(ch)}"

    # Check balanced quotes
    if query.count('"') % 2 != 0:
        return False, "Query has unclosed or unbalanced double quotes"

    # Check balanced parentheses and maximum nesting depth
    depth = 0
    max_depth = 0
    for ch in query:
        if ch == '(':
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch == ')':
            depth -= 1
            if depth < 0:
                return False, "Query has mismatched closing parenthesis"
    if depth != 0:
        return False, "Query has unclosed opening parenthesis"
    if max_depth > 4:
        return False, f"Query parenthesis nesting depth ({max_depth}) exceeds maximum limit (4)"

    # Check against global/destructive wildcards
    normalized_q = query.strip().lower()
    if normalized_q in ["*", "all", "is:unread", "is:read", "in:inbox", "in:anywhere"]:
        return False, "Dangerous global matching query detected"

    return True, "Valid"


def build_safe_gog_args(
    query: str,
    action: str = "--trash",
    client: Optional[str] = None
) -> Tuple[bool, List[str], str]:
    """
    Construct safe, non-shell argument array for gog CLI execution.
    Eliminates shell injection by using subprocess argv arrays (shell=False).
    """
    is_valid, reason = validate_gmail_query(query)
    if not is_valid:
        return False, [], reason

    if action not in ["--trash", "--never-spam", "--archive", "--mark-read"]:
        return False, [], f"Unsupported action flag: {action}"

    cmd = ["gog"]
    if client:
        cmd.extend(["--client", client])
    cmd.extend([
        "gmail",
        "settings",
        "filters",
        "create",
        "--query",
        query,
        action,
        "-y"
    ])
    return True, cmd, "Success"


def execute_safe_filter_create(
    query: str,
    action: str = "--trash",
    client: Optional[str] = None
) -> Dict[str, Any]:
    """Execute filter creation safely via subprocess (shell=False)."""
    valid, args, reason = build_safe_gog_args(query, action, client)
    if not valid:
        return {"success": False, "error": reason}

    try:
        res = subprocess.run(args, capture_output=True, text=True, timeout=15)
        if res.returncode != 0:
            return {"success": False, "error": res.stderr.strip() or res.stdout.strip()}
        return {"success": True, "output": res.stdout.strip()}
    except Exception as e:
        return {"success": False, "error": str(e)}
