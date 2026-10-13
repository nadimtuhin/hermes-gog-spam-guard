"""
Spam Clustering and Allowlist Recommendation Engine.
"""

from email.utils import parseaddr
import re
from typing import Dict, Any, List

# High-confidence phrase dictionaries for common spam campaigns
CAMPAIGN_RULES = [
    {
        "category": "casino_gambling",
        "label": "Casino & Gambling",
        "subject_phrases": ["Free Spins", "royal welcome", "MagicWin", "Fire_Jackpots", "Bonus bis zu"],
        "body_phrases": ["Casino Limitless", "Extreme Spins", "Millionaire's Life jackpot"]
    },
    {
        "category": "brand_phishing",
        "label": "Account & Brand Impersonation Phishing",
        "subject_phrases": [
            "photos and videos will be deleted",
            "Costco membership for free",
            "Sirius XM Will Be Removed",
            "Renew Cloud Hosting",
            "credit limit expires tonight",
            "Renew your subscription for free"
        ],
        "body_phrases": ["Sam'sClub", "Costco Account has expired"]
    },
    {
        "category": "compromised_relays_adult",
        "label": "Adult & Compromised Mail Relays",
        "from_domains": ["idime.com.co", "masivocapital.com.co"],
        "subject_phrases": ["Wake up rock hard", "sexual fantasies", "Will you make me happy"]
    },
    {
        "category": "miracle_cure_medical",
        "label": "Medical & Miracle Cure Clickbait",
        "subject_phrases": [
            "Water Glass Test",
            "Sciatic Pain in Hours",
            "cinnamon honey trick",
            "Beenden Sie Nagelpilz",
            "baking soda hack"
        ]
    }
]

# Known legitimate newsletters/services that should never be auto-trashed
REPUTABLE_SENDERS = [
    "evalsignal.xyz",
    "resiliens.com",
    "github.com",
    "google.com",
    "citybankplc.com",
    "thecitybank.com",
    "ebl-bd.com",
    "midlandbankbd.net",
    "chaldal.com",
    "upwork.com"
]


def extract_sender_domain(sender: str) -> str:
    """Extract authenticated domain from RFC 822 From address."""
    if not sender:
        return ""
    addr = parseaddr(sender)[1]
    return addr.rpartition("@")[2].lower().strip()


def is_reputable_sender(sender: str) -> bool:
    """
    Check if the sender email domain exactly matches or is a subdomain of an allowlisted domain.
    Prevents domain substring spoofing (e.g. 'alert@github.com.evil.ru').
    """
    domain = extract_sender_domain(sender)
    if not domain:
        return False
    return any(domain == rep or domain.endswith("." + rep) for rep in REPUTABLE_SENDERS)


def cluster_spam_messages(emails: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Classify a batch of clean emails into spam campaigns and detect
    false positives that require allowlisting.
    """
    # Build dictionary dynamically from CAMPAIGN_RULES
    clustered: Dict[str, List[Dict[str, Any]]] = {
        rule["category"]: [] for rule in CAMPAIGN_RULES
    }
    clustered["unmatched_spam"] = []
    clustered["recommended_allowlist"] = []

    for email in emails:
        sender = email.get("sender", "")
        subject = email.get("subject", "")
        snippet = email.get("snippet", "")
        domain = extract_sender_domain(sender)

        # Check if legitimate / misclassified mail
        if is_reputable_sender(sender):
            clustered["recommended_allowlist"].append(email)
            continue

        matched = False
        for rule in CAMPAIGN_RULES:
            # Check domain exact or subdomain match
            if "from_domains" in rule and any(domain == d or domain.endswith("." + d) for d in rule["from_domains"]):
                clustered[rule["category"]].append(email)
                matched = True
                break

            # Check subject phrases
            if "subject_phrases" in rule:
                for phrase in rule["subject_phrases"]:
                    if re.search(re.escape(phrase), subject, re.IGNORECASE):
                        clustered[rule["category"]].append(email)
                        matched = True
                        break
                if matched:
                    break

            # Check body phrases
            if "body_phrases" in rule:
                for phrase in rule["body_phrases"]:
                    if re.search(re.escape(phrase), snippet, re.IGNORECASE):
                        clustered[rule["category"]].append(email)
                        matched = True
                        break
                if matched:
                    break

        if not matched:
            clustered["unmatched_spam"].append(email)

    return clustered
