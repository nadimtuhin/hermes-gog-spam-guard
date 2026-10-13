"""
Command Line Interface for gog-spam-guard.
"""

import argparse
import json
import subprocess
import sys

from .sanitizer import sanitize_text, sanitize_notification_output
from .detector import detect_prompt_injection, process_spam_batch
from .validator import validate_gmail_query, execute_safe_filter_create
from .cluster import cluster_spam_messages


def cmd_scan(args):
    """Scan and sanitize spam emails via gog or local JSON file."""
    if args.file:
        with open(args.file) as f:
            raw_emails = json.load(f)
    else:
        # Fetch directly from gog
        gog_cmd = ["gog"]
        if args.client:
            gog_cmd.extend(["--client", args.client])
        gog_cmd.extend(["gmail", "search", "in:spam", f"--limit={args.limit}", "-j", "--results-only"])
        try:
            res = subprocess.run(gog_cmd, capture_output=True, text=True, check=True, timeout=30)
            raw_emails = json.loads(res.stdout) if res.stdout.strip() else []
        except Exception as e:
            print(f"Error fetching from gog CLI: {e}", file=sys.stderr)
            sys.exit(1)

    result = process_spam_batch(raw_emails)
    print(f"Total Emails Processed: {len(raw_emails)}")
    print(f"Safe Messages:          {result['safe_count']}")
    print(f"Quarantined Messages:   {result['quarantined_count']}")

    if result["quarantined"]:
        print("\n[!] Quarantined Injection Attempts:")
        for q in result["quarantined"]:
            print(f"  - #{q['id']} From: {q['sender']}")
            rule = q.get('matched_rule') or q.get('matched_pattern')
            print(f"    Reason: {q['reason']} ({rule})")
            print(f"    Subject: {q['sanitized_subject']}")

    # Cluster safe messages
    clusters = cluster_spam_messages(result["safe_emails"])
    print("\n[+] Clustered Spam Campaigns:")
    for cat, items in clusters.items():
        if items:
            print(f"  {cat}: {len(items)} messages")

    if clusters["recommended_allowlist"]:
        print("\n[*] Recommended Senders to Allowlist (--never-spam):")
        for item in clusters["recommended_allowlist"]:
            print(f"  - {item['sender']} | Subj: {item['subject']}")


def cmd_check(args):
    """Check text or string for prompt injection signatures."""
    detected, pattern = detect_prompt_injection(args.text)
    if detected:
        print(f"[!] INJECTION DETECTED: {pattern}")
        sys.exit(2)
    else:
        print("[✓] Clean: No prompt injection detected.")


def cmd_validate_query(args):
    """Validate a Gmail search/filter query for shell safety and balanced syntax."""
    valid, reason = validate_gmail_query(args.query)
    if valid:
        print(f"[✓] Valid query: {args.query}")
    else:
        print(f"[!] Invalid query: {reason}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="hermes-gog-spam-guard",
        description="Prompt injection firewall and server-side Gmail filter generator for Hermes Agent."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan command
    p_scan = subparsers.add_parser("scan", help="Scan and sanitize spam messages")
    p_scan.add_argument("--file", help="Path to local JSON spam export")
    p_scan.add_argument("--client", help="Optional gog client profile")
    p_scan.add_argument("--limit", type=int, default=50, help="Max emails to scan (default 50)")
    p_scan.set_defaults(func=cmd_scan)

    # check command
    p_check = subparsers.add_parser("check", help="Test a string for prompt injection signatures")
    p_check.add_argument("text", help="Text string to evaluate")
    p_check.set_defaults(func=cmd_check)

    # validate-query command
    p_val = subparsers.add_parser("validate-query", help="Validate a Gmail filter query")
    p_val.add_argument("query", help="Gmail query string to validate")
    p_val.set_defaults(func=cmd_validate_query)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
