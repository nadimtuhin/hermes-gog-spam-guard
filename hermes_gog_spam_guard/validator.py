"""
Gmail Filter Query Validator and Safe Non-Shell Command Builder.
"""

import json
import re
import subprocess
from typing import Tuple, List, Optional, Dict, Any

NEGATION_RE = re.compile(r'(?:^|[\s(])-')
BROAD_OPERATOR_RE = re.compile(r'\*|\b(?:in|is|larger|smaller|after|before|older_than|newer_than|has|label|category):', re.I)
ANCHOR_RE = re.compile(r'\b(?:from|subject):', re.I)
FORBIDDEN_SHELL_CHARS = [";", "`", "$", "\n", "\r", "\\", "{", "}", "<", ">"]


def validate_gmail_query(query: str) -> Tuple[bool, str]:
    """
    Validate that a Gmail filter query is safe to execute and does not contain
    shell metacharacters, syntax bombs, or dangerous wildcard patterns.
    Enforces anchor to 'from:' or 'subject:', disallows negation and broad operators.
    """
    if not query or len(query.strip()) == 0:
        return False, "Query cannot be empty"

    if len(query) > 300:
        return False, "Query exceeds maximum safe length (300 chars)"

    # Strict check for shell metacharacters
    for ch in FORBIDDEN_SHELL_CHARS:
        if ch in query:
            return False, f"Query contains illegal shell character: {repr(ch)}"

    # Check for CLI flag injection attempts (e.g. --help, -y)
    stripped = query.strip()
    if stripped.startswith("-") or "--" in stripped:
        return False, "Query cannot start with hyphen or contain flag injections ('--')"

    # Reject negation operators that invert filter scope to match all non-spam mail
    if NEGATION_RE.search(stripped):
        return False, "Negated operators (e.g. -in:spam, -from:) are not allowed in automated filter creation"

    # Reject broad search operators
    if BROAD_OPERATOR_RE.search(stripped):
        return False, "Broad operators (*, in:, is:, larger:, after:, etc.) are not allowed in automated filter creation"

    # Must target specific from: or subject: selectors
    if not ANCHOR_RE.search(stripped):
        return False, "Query must be explicitly anchored to 'from:' or 'subject:' criteria"

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

    return True, "Valid"


def build_safe_gog_args(
    query: str,
    action: str = "--trash",
    client: Optional[str] = None
) -> Tuple[bool, List[str], str]:
    """
    Construct safe, non-shell argument array for gog CLI execution.
    Eliminates shell injection by using subprocess argv arrays (shell=False)
    and passes query as a unified flag entry '--query=<query>' to prevent flag collision.
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
        f"--query={query}",
        action,
        "-y"
    ])
    return True, cmd, "Success"


def check_inbox_dry_run(query: str, client: Optional[str] = None) -> Tuple[bool, int, str]:
    """
    Dry-run check: verify that a candidate filter query returns 0 hits in the live inbox.
    Returns (safe_to_trash, hit_count, error_or_warning).
    """
    check_cmd = ["gog"]
    if client:
        check_cmd.extend(["--client", client])
    check_cmd.extend([
        "gmail",
        "search",
        f"({query}) in:inbox",
        "--limit=5",
        "-j",
        "--results-only"
    ])
    try:
        res = subprocess.run(check_cmd, capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            return False, -1, f"Dry-run search failed: {res.stderr.strip()}"
        hits = json.loads(res.stdout) if res.stdout.strip() else []
        count = len(hits)
        if count > 0:
            return False, count, f"Dangerous: Query matched {count} message(s) currently in INBOX"
        return True, 0, "Clean: 0 inbox hits"
    except Exception as e:
        return False, -1, f"Dry-run check error: {str(e)}"


def execute_safe_filter_create(
    query: str,
    action: str = "--trash",
    client: Optional[str] = None,
    skip_dry_run: bool = False
) -> Dict[str, Any]:
    """
    Execute filter creation safely via subprocess (shell=False).
    Runs inbox dry-run check before applying destructive '--trash' actions.
    """
    valid, args, reason = build_safe_gog_args(query, action, client)
    if not valid:
        return {"success": False, "error": reason}

    # Pre-flight inbox safety check for destructive trash actions
    if action == "--trash" and not skip_dry_run:
        safe, count, msg = check_inbox_dry_run(query, client)
        if not safe:
            return {
                "success": False,
                "error": f"Refusing to apply --trash filter: {msg}. Query would affect legitimate mail."
            }

    try:
        res = subprocess.run(args, capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            return {"success": False, "error": res.stderr.strip() or res.stdout.strip()}
        return {"success": True, "output": res.stdout.strip()}
    except Exception as e:
        return {"success": False, "error": str(e)}
