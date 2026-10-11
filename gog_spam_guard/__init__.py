"""
GOG Spam Guard - Prompt injection firewall and server-side filter generator for Gmail.
"""

from .sanitizer import (
    sanitize_text,
    canonicalize_text,
    desmear_fragmented_words,
    unescape_all_entities,
    sanitize_notification_output,
)
from .detector import (
    detect_prompt_injection,
    detect_encoded_payload,
    detect_acrostic_payload,
    calculate_shannon_entropy,
    is_suspicious_high_entropy,
    process_spam_batch,
)
from .validator import (
    validate_gmail_query,
    build_safe_gog_args,
    execute_safe_filter_create,
)
from .cluster import (
    cluster_spam_messages,
    is_reputable_sender,
)

__version__ = "0.1.0"
__all__ = [
    "sanitize_text",
    "canonicalize_text",
    "desmear_fragmented_words",
    "unescape_all_entities",
    "sanitize_notification_output",
    "detect_prompt_injection",
    "detect_encoded_payload",
    "detect_acrostic_payload",
    "calculate_shannon_entropy",
    "is_suspicious_high_entropy",
    "process_spam_batch",
    "validate_gmail_query",
    "build_safe_gog_args",
    "execute_safe_filter_create",
    "cluster_spam_messages",
    "is_reputable_sender",
]
