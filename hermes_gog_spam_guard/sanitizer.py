"""
Text Sanitizer and Normalization Pipeline for untrusted email inputs.
"""

import html
import re
import unicodedata

# Comprehensive invisible marks: zero-width, BiDi overrides, soft hyphens,
# word joiners (U+2060-U+2064), Mongolian vowel separator (U+180E), variation selectors (U+FE00-U+FE0F),
# and Plane 14 invisible tag characters (U+E0000-U+E007F, U+E0100-U+E01EF).
INVISIBLE_AND_CONTROL_RE = re.compile(
    r"["
    r"\u200B-\u200F\u2060-\u2064\uFEFF\u202A-\u202E\u2066-\u2069"
    r"\u180E\uFE00-\uFE0F"
    r"\U000E0000-\U000E007F\U000E0100-\U000E01EF"
    r"\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\xAD"
    r"]"
)

# Common Cyrillic and Greek homoglyphs mapped to ASCII equivalents
CONFUSABLES_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'п': 'n',
    'т': 't', 'в': 'b', 'к': 'k', 'м': 'm', 'н': 'h',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J',
    'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X', 'Ү': 'Y',
    'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v',
    'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M',
    'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X'
}
CONFUSABLES_TRANS = str.maketrans(CONFUSABLES_MAP)

# Leetspeak translation table (0->o, 1->i, 3->e, 4->a, 5->s, 7->t, @->a, $->s)
LEET_MAP = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's'
}
LEET_TRANS = str.maketrans(LEET_MAP)

# Model boundary and role tokens across major architectures (ChatML, Llama, Claude, Hermes)
MODEL_TOKENS_RE = re.compile(
    r"(?:"
    r"<\|(?:im_start|im_end|system|user|assistant|endoftext|extra_\d+)\|>"
    r"|\[\/?INST\]|<<\/?SYS>>|<\/?s>|<start_of_turn>|<end_of_turn>"
    r"|\n\nHuman:|\n\nAssistant:"
    r"|\[\/?(?:SYSTEM|OUT-OF-BAND|OUT-OF-BAND USER MESSAGE|HUMAN|ASSISTANT|ADMIN|USER|INSTRUCTION|CONTEXT)[^\]]*\]"
    r"|<\/?(?:system|instruct|instruction|prompt|context|admin|tool_call|tool_result)[^>]*>"
    r"|```"
    r")",
    re.IGNORECASE
)

# Markdown & HTML exfiltration patterns
EXFILTRATION_RE = re.compile(
    r"(?:"
    r"!\[.*?\]\s*\(\s*https?:\/\/[^\s\)]+\?[^\s\)]*\)|"
    r"<img[^>]+src=[\"']https?:\/\/[^\"']+\?[^\"']*[\"']|"
    r"data:text\/html;base64,"
    r")",
    re.IGNORECASE
)

# Synthetic context / turn boundary spoofing
TURN_SPOOFING_RE = re.compile(
    r"(?:"
    r"(?:^|\n)\s*(?:---|===|\*\*\*)\s*(?:CUT HERE|END OF (?:INPUT|EMAIL)|BEGIN (?:SYSTEM|USER|AGENT|PROMPT)|USER PROMPT|HUMAN INPUT)\s*(?:---|===|\*\*\*)|"
    r"(?:^|\n)\s*(?:USER CORRECTION|SYSTEM OVERRIDE|ADMIN DIRECTIVE)\s*:|"
    r"(?:^|\n)\s*Example\s+\d+\s*:\s*(?:Input|User):"
    r")",
    re.IGNORECASE
)

# Agent trajectory markers (scratchpad hijacking)
TRAJECTORY_POISONING_RE = re.compile(
    r"(?:"
    r"(?:^|\n)\s*Thought\s*:[^\n]*\n\s*Action\s*:|"
    r"(?:^|\n)\s*Action\s*:\s*(?:terminal|execute_code|bash|sh|browser|write_file|patch|read_file)|"
    r"(?:^|\n)\s*Action\s*Input\s*:|"
    r"(?:^|\n)\s*Observation\s*:|"
    r"(?:^|\n)\s*Tool\s*Result\s*:|"
    r"(?:^|\n)\s*Agent\s*Response\s*:"
    r")",
    re.IGNORECASE
)


def desmear_fragmented_words(text: str) -> str:
    """De-smear token fragmentation where words are split with punctuation."""
    def repl(m):
        full = m.group(0)
        return re.sub(r"[.\-_]", "", full)

    smear_pat = r"\b[a-zA-Z](?:[.\-_][a-zA-Z])+\b"
    return re.sub(smear_pat, repl, text)


def canonicalize_text(text: str) -> str:
    """
    Apply full canonicalization:
      1. Decompose via NFKD to split combining diacritics and accents
      2. Strip all combining marks and Zalgo characters
      3. Strip all zero-width, invisible tags (Plane 14), and BiDi overrides
      4. Normalize back to NFKC
      5. Substitute Cyrillic and Greek homoglyphs to ASCII
    """
    if not text:
        return ""
    decomposed = unicodedata.normalize("NFKD", text)
    without_marks = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    visible = INVISIBLE_AND_CONTROL_RE.sub("", without_marks)
    normalized = unicodedata.normalize("NFKC", visible)
    unconfused = normalized.translate(CONFUSABLES_TRANS)
    return unconfused


def unescape_all_entities(text: str) -> str:
    """Decode HTML numeric/hex entities and string hex escapes."""
    if not text:
        return ""
    unescaped = html.unescape(text)
    def hex_repl(m):
        try:
            return bytes.fromhex(m.group(1)).decode("utf-8", errors="ignore")
        except Exception:
            return m.group(0)
    unescaped = re.sub(r"\\x([0-9a-fA-F]{2})", hex_repl, unescaped)
    return unescaped


def sanitize_text(text: str) -> str:
    """Normalize text, strip control characters, and remove model role boundary tokens."""
    if not text:
        return ""
    canonical = canonicalize_text(text)
    cleaned = MODEL_TOKENS_RE.sub(" ", canonical)
    cleaned = EXFILTRATION_RE.sub(" ", cleaned)
    cleaned = TURN_SPOOFING_RE.sub(" ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def sanitize_notification_output(text: str) -> str:
    """
    Dual-sided firewall: sanitize agent summary text before delivery to Telegram or channels.
    Strips raw markdown image embeds, dangerous javascript/data links, and unescaped HTML.
    Also strips sensitive query parameters from tracking URLs to prevent silent exfiltration.
    """
    if not text:
        return ""
    cleaned = re.sub(r"!\[.*?\]\([\s\S]*?\)", "[IMAGE REMOVED]", text)
    cleaned = re.sub(r"\[([^\]]+)\]\((?i:(?:javascript|data|vbscript)):[^\)]*\)", r"\1", cleaned)
    cleaned = re.sub(r"<\/?(?i:(?:script|iframe|embed|object|meta))[^>]*>", "", cleaned)
    # Strip tracking query strings from external markdown links
    cleaned = re.sub(r"\[([^\]]+)\]\(https?:\/\/[^\s\)]+\?[^\s\)]*\)", r"\1 [link sanitized]", cleaned)
    return cleaned
