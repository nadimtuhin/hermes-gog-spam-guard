"""
Prompt Injection Detection, Steganography Decoder, and Heuristic Firewall.
"""

import base64
import codecs
import math
import re
import urllib.parse
from typing import Dict, Any, List, Tuple, Optional

from .sanitizer import (
    sanitize_text,
    desmear_fragmented_words,
    unescape_all_entities,
    LEET_TRANS,
    TRAJECTORY_POISONING_RE,
    TURN_SPOOFING_RE
)

# Raw JSON tool-call / role smuggling
JSON_TOOL_SPOOF_RE = re.compile(
    r"(?:"
    r"\"tool_calls\"\s*:\s*\[|"
    r"\"function_call\"\s*:\s*\{|"
    r"\"role\"\s*:\s*\"(?:assistant|system|tool)\""
    r")",
    re.IGNORECASE
)

# System prompt / Canary extraction probes
SYSTEM_EXTRACTION_RE = re.compile(
    r"(?:"
    r"\b(?:repeat|print|reveal|output|display|show|dump|echo)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|instructions\s+above|rules|developer\s+prompt|canary)\b|"
    r"\bwhat\s+(?:are\s+)?(?:your\s+)?(?:initial\s+|developer\s+|system\s+)?(?:instructions|rules|system\s+prompt)\b|"
    r"\bverbatim\s+copy\s+of\s+(?:the\s+)?(?:prompt|system\s+instructions)\b"
    r")",
    re.IGNORECASE
)

# Negative constraint inversion
CONSTRAINT_INVERSION_RE = re.compile(
    r"(?:"
    r"\b(?:do\s+not|never|refuse\s+to|stop)\s+(?:filter|trash|block|label|quarantine)\b[^\.\n]{0,40}\b(?:email|message|sender|spam)\b|"
    r"\b(?:it\s+is\s+forbidden\s+to|you\s+must\s+never)\s+follow\s+(?:your\s+)?(?:rules|instructions)\b"
    r")",
    re.IGNORECASE
)

# Multilingual instruction override signatures
MULTILINGUAL_INJECTION_RE = re.compile(
    r"(?:"
    r"\b(?:ignorier(?:en|e)?|vergiss)\b[^\.\n]{0,40}\b(?:anweisungen|instruktionen|regeln)\b|"
    r"\b(?:ignora|olvida|descarta)\b[^\.\n]{0,40}\b(?:instrucciones|reglas|directivas)\b|"
    r"\b(?:ignorez?|oublie(?:z)?)\b[^\.\n]{0,40}\b(?:instructions|directives|consignes)\b|"
    r"\b(?:игнорируй(?:те)?|забудь(?:те)?)\b[^\.\n]{0,40}\b(?:инструкци[ий]|правил[ао])\b|"
    r"(?:忽略|无视|丢弃)[^\.\n]{0,20}(?:指令|指示|提示词|规则)|"
    r"(?:指示|ルール|プロンプト)[^\.\n]{0,20}(?:無視|破棄)|"
    r"(?:تجاهل|الغاء|تجاوز)[^\.\n]{0,25}(?:التعليمات|الأوامر|القواعد|السابقة)|"
    r"(?:نادیده\s+بگیرید|فراموش\s+کنید)[^\.\n]{0,25}(?:دستورالعمل|دستورات|قوانین)|"
    r"(?:이전|앞선)?\s*(?:지시|명령|지침|규칙)[^\.\n]{0,20}(?:무시|취소|삭제)|"
    r"(?:पिछले|पूर्व)\s*(?:सभी\s*)?(?:निर्देशों|आदेशों|नियमों)[^\.\n]{0,20}(?:अनदेखा|रद्द)"
    r")",
    re.IGNORECASE
)

# Out-of-band DNS/Webhook exfiltration targets
OOB_EXFIL_RE = re.compile(
    r"(?:"
    r"\b(?:dig|nslookup|host)\s+[\$\w\.\/\:\-]+|"
    r"\b(?:oastify\.com|burpcollaborator\.net|canarytokens\.com|requestbin\.com|webhook\.site|interactsh\.com)\b"
    r")",
    re.IGNORECASE
)

# Jailbreak paradigms & persona coercion
JAILBREAK_RE = re.compile(
    r"(?:"
    r"\b(?:dan|aim|stan|jailbreak|unrestricted mode)\b|"
    r"\b(?:pretend|roleplay|imagine|act)\s+(?:as\s+)?(?:you are|to be|an?)\s+(?:unrestricted|evil|different|hacker|root|admin)|"
    r"\bhypothetical\s+(?:scenario|situation)\s+where\s+you\s+(?:have\s+no\s+rules|can\s+execute)|"
    r"\bdo\s+anything\s+now\b"
    r")",
    re.IGNORECASE
)

# Tool / Agent internal API abuse
TOOL_ABUSE_RE = re.compile(
    r"(?:"
    r"\b(?:call|invoke|execute|trigger|use)\s+(?:the\s+)?(?:terminal|write_file|patch|read_file|memory|delegate_task|execute_code|process_manage)\b|"
    r"\bhermes\s+config\s+set\b|"
    r"\bhermes\s+auth\b"
    r")",
    re.IGNORECASE
)

# Agent worm and self-replication payloads
WORM_REPLICATION_RE = re.compile(
    r"(?:"
    r"\b(?:copy|reproduce|include|forward|echo)\s+this\s+(?:exact\s+)?(?:text|prompt|message|instruction|code)\s+(?:in|into|to)\s+(?:your\s+)?(?:next\s+)?(?:response|turn|output|summary|email|message)\b|"
    r"\bpass\s+this\s+(?:prompt|message)\s+along\s+to\b"
    r")",
    re.IGNORECASE
)

# Refusal suppression and constraint disabling
REFUSAL_SUPPRESSION_RE = re.compile(
    r"(?:"
    r"\b(?:do\s+not|never)\s+(?:say|respond\s+with|refuse|apologize|state)\s+(?:that\s+)?(?:you\s+cannot|as\s+an\s+ai|i\s+cannot|i\s+am\s+unable)\b|"
    r"\b(?:refusal|apology)\s+is\s+(?:strictly\s+)?forbidden\b|"
    r"\byou\s+are\s+not\s+allowed\s+to\s+say\s+no\b"
    r")",
    re.IGNORECASE
)

# Persistent memory / state poisoning attempts
MEMORY_POISON_RE = re.compile(
    r"(?:"
    r"\b(?:remember|save|persist|store)\s+(?:this\s+)?(?:in|to)\s+(?:persistent\s+)?memory\b|"
    r"\b(?:add|update)\s+(?:to\s+)?(?:user\s+)?(?:profile|memory)\s*:|"
    r"\bset\s+user\s+preference\s*:"
    r")",
    re.IGNORECASE
)

# Code-interpreter and script smuggling
CODE_SMUGGLING_RE = re.compile(
    r"(?:"
    r"\b(?:eval|compile|exec|__import__)\s*\(|"
    r"os\.system\s*\(|"
    r"subprocess\.(?:run|Popen|call)\s*\(|"
    r"<script\b[^>]*>[\s\S]*?<\/script>|"
    r"<(?:iframe|embed|object|meta|applet|base)\b[^>]*>|"
    r"(?:javascript|vbscript):"
    r")",
    re.IGNORECASE
)

# Goal and task subversion
GOAL_SUBVERSION_RE = re.compile(
    r"(?:"
    r"\b(?:the\s+user\s+has|operator\s+has)\s+(?:canceled|cancelled|changed|revoked)\s+(?:this\s+)?(?:request|task|goal)\b|"
    r"\b(?:your\s+new\s+goal\s+is|new\s+objective\s+is)\s*:|"
    r"\b(?:the\s+user\s+has\s+already\s+approved|pre-approved\s+by\s+user|no\s+confirmation\s+needed)\b"
    r")",
    re.IGNORECASE
)

# Secret harvest and environment variable probing
SECRET_HARVEST_RE = re.compile(
    r"(?:"
    r"\b(?:print|echo|show|output|leak|cat)\s+.*(?:\$[A-Z_]+_KEY|\$[A-Z_]+_TOKEN|\$[A-Z_]+_SECRET|\bprocess\.env\b|\bos\.environ\b|\.env\b)|"
    r"\b(?:OPENROUTER|ANTHROPIC|OPENAI|GROQ|AWS|GITHUB|GOG)_(?:API_KEY|TOKEN|SECRET)\b"
    r")",
    re.IGNORECASE
)

# Credential harvesting form / template smuggling
CREDENTIAL_FORM_RE = re.compile(
    r"(?:"
    r"\b(?:enter|input|provide|submit)\s+(?:your\s+)?(?:password|api[_\s-]?key|private[_\s-]?key|secret|token|credentials)\b|"
    r"\|\s*(?:password|api[_\s-]?key|secret|token)\s*\|"
    r")",
    re.IGNORECASE
)

# Synthetic developer / system markdown header spoofing
SYSTEM_HEADER_SPOOF_RE = re.compile(
    r"(?:"
    r"(?:^|\n)\s*#{1,6}\s*(?:SYSTEM|DEVELOPER|INSTRUCTION|AGENT|ADMIN|OPERATOR|PROMPT)\s*(?:OVERRIDE|DIRECTIVE|INSTRUCTION|NOTE)?\s*[:\n]|"
    r"(?:^|\n)\s*>>>\s*(?:SYSTEM|DEVELOPER|AGENT|INSTRUCTION)(?:\s+(?:OVERRIDE|DIRECTIVE|INSTRUCTION))?\s*<<<"
    r")",
    re.IGNORECASE
)

# Multi-turn conversational dialogue transcript smuggling
CONVERSATIONAL_SPOOF_RE = re.compile(
    r"(?:\b(?:Human|User|Operator|Admin):\s*.*\n\s*(?:Assistant|Bot|AI|Model):\s*)",
    re.IGNORECASE
)

# Dangerous code fence execution smuggling
CODE_FENCE_EXECUTION_RE = re.compile(
    r"```(?:bash|sh|zsh|shell|python)?\s*[\s\S]*?(?:curl|wget|rm\s+-rf|os\.system|subprocess\.|exec|eval)[\s\S]*?```",
    re.IGNORECASE
)

# Direct prompt injection signatures
INJECTION_SIGNATURES = [
    r"(?:disregard|ignore|bypass|drop|delete|forget)\s+(?:all\s+)?(?:prior|previous|past|above|system)\s+(?:instructions|prompts|rules|directives)",
    r"(?:new|updated|revised)\s+(?:system\s+)?instructions\s*:",
    r"you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|different|evil|jailbroken|admin|developer|dan)",
    r"system\s*prompt\s*override",
    r"developer\s+mode\s+(?:enabled|activated|on)",
    r"(?:admin|administrator|workspace\s+admin|google\s+security\s+team|nadim)\s+(?:override|notice|alert|order)\s*:",
    r"(?:urgent|important)\s*:\s*(?:do\s+not\s+filter|whitelist\s+this|disable\s+spam\s+filter)",
    r"\b(?:curl|wget|nc|bash|sh|zsh)\b\s+[\w\.\/\:\-]+",
    r"\brm\s+-rf\s+[\w\.\/\:\-]+",
    r"(?:send|exfiltrate|print|cat|leak|upload)\s+(?:all\s+)?(?:keys|tokens|passwords|credentials|\.env|id_rsa|keychain|auth\.json)",
    r"create\s+(?:a\s+)?filter\s+to\s+trash\s+everything",
    r"trash\s+all\s+(?:incoming\s+)?emails",
    r"delete\s+all\s+(?:gmail\s+)?filters"
]
INJECTION_RE = re.compile("|".join(INJECTION_SIGNATURES), re.IGNORECASE)

ACROSTIC_DANGEROUS_WORDS = {"DISREGARD", "IGNORE", "DELETE", "TRASH", "OVERRIDE"}


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        entropy += - p_x * math.log(p_x, 2)
    return entropy


def is_suspicious_high_entropy(text: str) -> bool:
    """Detect dense random/encrypted blobs (length >= 40, entropy >= 4.9 without spaces)."""
    words = text.split()
    for w in words:
        if len(w) >= 40 and calculate_shannon_entropy(w) >= 4.9:
            return True
    return False


def detect_acrostic_payload(text: str) -> Tuple[bool, Optional[str]]:
    """Detect acrostic steganography where initials of consecutive words form attack verbs."""
    words = re.findall(r"\b[A-Za-z]+\b", text)
    if len(words) < 5:
        return False, None
    initials = "".join([w[0].upper() for w in words])
    for target in ACROSTIC_DANGEROUS_WORDS:
        if target in initials:
            return True, f"acrostic_payload: {target}"
    return False, None


def _has_injection_heuristics(text: str) -> Tuple[bool, Optional[str]]:
    """Evaluate text heuristics against known injection, jailbreak, and abuse patterns."""
    multi_raw_match = MULTILINGUAL_INJECTION_RE.search(text)
    if multi_raw_match:
        return True, f"multilingual_injection: {multi_raw_match.group(0)}"

    sanitized = sanitize_text(text)

    match = INJECTION_RE.search(sanitized)
    if match:
        return True, match.group(0)

    multi_match = MULTILINGUAL_INJECTION_RE.search(sanitized)
    if multi_match:
        return True, f"multilingual_injection: {multi_match.group(0)}"

    extract_match = SYSTEM_EXTRACTION_RE.search(sanitized)
    if extract_match:
        return True, f"canary_extraction_probe: {extract_match.group(0)}"

    neg_match = CONSTRAINT_INVERSION_RE.search(sanitized)
    if neg_match:
        return True, f"constraint_inversion: {neg_match.group(0)}"

    jb_match = JAILBREAK_RE.search(sanitized)
    if jb_match:
        return True, f"jailbreak_attempt: {jb_match.group(0)}"

    tool_match = TOOL_ABUSE_RE.search(sanitized)
    if tool_match:
        return True, f"tool_abuse: {tool_match.group(0)}"

    worm_match = WORM_REPLICATION_RE.search(sanitized)
    if worm_match:
        return True, f"worm_replication_attempt: {worm_match.group(0)}"

    refusal_match = REFUSAL_SUPPRESSION_RE.search(sanitized)
    if refusal_match:
        return True, f"refusal_suppression: {refusal_match.group(0)}"

    mem_match = MEMORY_POISON_RE.search(sanitized)
    if mem_match:
        return True, f"memory_poisoning: {mem_match.group(0)}"

    code_match = CODE_SMUGGLING_RE.search(sanitized)
    if code_match:
        return True, f"code_smuggling: {code_match.group(0)}"

    goal_match = GOAL_SUBVERSION_RE.search(sanitized)
    if goal_match:
        return True, f"goal_subversion: {goal_match.group(0)}"

    secret_match = SECRET_HARVEST_RE.search(sanitized)
    if secret_match:
        return True, f"secret_harvesting: {secret_match.group(0)}"

    cred_match = CREDENTIAL_FORM_RE.search(sanitized)
    if cred_match:
        return True, f"credential_form_smuggling: {cred_match.group(0)}"

    oob_match = OOB_EXFIL_RE.search(sanitized)
    if oob_match:
        return True, f"oob_exfiltration: {oob_match.group(0)}"

    desmeared = desmear_fragmented_words(sanitized)
    if desmeared != sanitized:
        desmear_match = INJECTION_RE.search(desmeared)
        if desmear_match:
            return True, f"fragmented_injection: {desmear_match.group(0)}"

    leeted = sanitized.translate(LEET_TRANS)
    if leeted != sanitized:
        leet_match = INJECTION_RE.search(leeted)
        if leet_match:
            return True, f"leetspeak_injection: {leet_match.group(0)}"

    return False, None


def detect_encoded_payload(text: str) -> Tuple[bool, Optional[str]]:
    """Inspect text for Base64, URL-encoded, ROT13, 8-bit binary, reverse text, or whitespace stego."""
    if not text:
        return False, None

    if "%" in text:
        try:
            unquoted = urllib.parse.unquote(text)
            if unquoted != text:
                has_inj, pat = _has_injection_heuristics(unquoted)
                if has_inj:
                    return True, f"url_encoded_injection: {pat}"
        except Exception:
            pass

    b64_matches = re.findall(r"(?:^|(?<=\s))[A-Za-z0-9+/]{16,}={0,2}(?=\s|$|[.,;!])", text)
    for blob in b64_matches:
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", errors="ignore")
            if len(decoded) > 10:
                has_inj, pat = _has_injection_heuristics(decoded)
                if has_inj:
                    return True, f"base64_injection: {pat}"
        except Exception:
            continue

    binary_matches = re.findall(r"(?:[01]{8}\s+){3,}[01]{8}", text)
    for b_str in binary_matches:
        try:
            bytes_list = [int(b, 2) for b in b_str.split()]
            decoded_ascii = bytes(bytes_list).decode("utf-8", errors="ignore")
            if len(decoded_ascii) >= 4:
                has_inj, pat = _has_injection_heuristics(decoded_ascii)
                if has_inj:
                    return True, f"binary_encoded_injection: {pat}"
        except Exception:
            continue

    words = text.split()
    if len(words) >= 3:
        try:
            rot13_candidate = codecs.decode(text, "rot_13")
            has_inj, pat = _has_injection_heuristics(rot13_candidate)
            if has_inj:
                return True, f"rot13_injection: {pat}"
        except Exception:
            pass

    if len(words) >= 3:
        has_rev_inj, rev_pat = _has_injection_heuristics(text[::-1])
        if has_rev_inj:
            return True, f"reverse_text_injection: {rev_pat}"

        per_word_rev = " ".join([w[::-1] for w in words])
        has_pw_inj, pw_pat = _has_injection_heuristics(per_word_rev)
        if has_pw_inj:
            return True, f"reverse_text_injection: {pw_pat}"

    if re.search(r"[ \t]{8,}$", text, re.MULTILINE):
        return True, "whitespace_steganography"

    return False, None


def detect_prompt_injection(text: str) -> Tuple[bool, Optional[str]]:
    """
    Comprehensive multi-layer prompt injection detection.
    """
    if not text:
        return False, None

    if TRAJECTORY_POISONING_RE.search(text):
        return True, "trajectory_poisoning"

    if TURN_SPOOFING_RE.search(text):
        return True, "turn_spoofing"

    if SYSTEM_HEADER_SPOOF_RE.search(text):
        return True, "system_header_spoofing"

    if CONVERSATIONAL_SPOOF_RE.search(text):
        return True, "conversational_spoofing"

    if CODE_FENCE_EXECUTION_RE.search(text):
        return True, "code_fence_smuggling"

    if JSON_TOOL_SPOOF_RE.search(text):
        return True, "json_tool_smuggling"

    if is_suspicious_high_entropy(text):
        return True, "high_entropy_anomaly"

    has_acrostic, acrostic_pat = detect_acrostic_payload(text)
    if has_acrostic:
        return True, acrostic_pat

    unescaped = unescape_all_entities(text)
    if unescaped != text:
        has_unesc_inj, unesc_pat = _has_injection_heuristics(unescaped)
        if has_unesc_inj:
            return True, f"entity_escaped_injection: {unesc_pat}"

    encoded_inj, enc_pat = detect_encoded_payload(text)
    if encoded_inj:
        return True, enc_pat

    return _has_injection_heuristics(text)


def process_spam_batch(raw_emails: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Sanitize incoming spam emails, flag injection attempts, and separate clean metadata."""
    safe_emails = []
    quarantined = []

    for email in raw_emails:
        raw_subj = email.get("subject", "")
        raw_body = email.get("content", "")
        sender = email.get("sender", "")

        subj_inj, subj_pat = detect_prompt_injection(raw_subj)
        body_inj, body_pat = detect_prompt_injection(raw_body)

        if subj_inj or body_inj:
            quarantined.append({
                "id": email.get("id"),
                "sender": sanitize_text(sender),
                "reason": "prompt_injection_detected",
                "matched_pattern": subj_pat or body_pat,
                "sanitized_subject": sanitize_text(raw_subj)[:100]
            })
            continue

        safe_emails.append({
            "id": email.get("id"),
            "sender": sanitize_text(sender),
            "subject": sanitize_text(raw_subj)[:150],
            "date": email.get("date"),
            "snippet": sanitize_text(raw_body)[:100]
        })

    return {
        "safe_count": len(safe_emails),
        "quarantined_count": len(quarantined),
        "safe_emails": safe_emails,
        "quarantined": quarantined
    }
