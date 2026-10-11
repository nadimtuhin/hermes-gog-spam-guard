# hermes-gog-spam-guard

> Prompt injection firewall, boundary sanitizer, and server-side Gmail filter automation engine for Hermes Agent.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests: 39 passing](https://img.shields.io/badge/tests-39%20passing-brightgreen.svg)]()
[![Dependencies: Zero](https://img.shields.io/badge/dependencies-zero-green.svg)]()

Autonomous coding agents (Hermes, Claude Code, OpenManus, CrewAI) frequently need inbox access to triage notifications, scrape alerts, or manage spam. 

However, **incoming spam is an untrusted security boundary**. Attackers actively weaponize spam emails with indirect prompt injection, delimiter hijacking, zero-width steganography, and hidden tool-call payloads to trick agents into leaking environment variables, deleting legitimate mail, or running unauthorized shell commands.

`hermes-gog-spam-guard` is a deterministic, zero-dependency firewall that intercepts and sanitizes email streams before they ever touch LLM context, evaluates spam campaigns in an isolated sandbox, and safely generates permanent server-side Gmail filters using the [`gog` CLI](https://github.com/google/gogcli).

---

## Threat Model & Mitigations

| Attack Vector | Evasion Technique | `hermes-gog-spam-guard` Defense |
|---|---|---|
| **Homoglyph & Confusables** | Cyrillic/Greek lookalikes (`dіѕrеgаrd`) | Canonicalizes homoglyphs to ASCII before regex/heuristics |
| **Invisible Tags (Plane 14)** | Unicode tags (`U+E0001` - `U+E007F`) | Explicit plane stripping of invisible steganography bytes |
| **Token Fragmentation** | Punctuated words (`d.i.s.r.e.g.a.r.d`, `i_g_n_o_r_e`) | De-smears fragmented tokens into continuous words |
| **Zalgo / Combining Marks** | Stacked diacritics (`d̵i̴s̸r̸e̷g̵a̸r̵d̷`) | Strips `\u0300-\u036F` combining characters and soft hyphens |
| **Leetspeak Obfuscation** | Number replacements (`1gn0r3 4ll pr10r`) | Leetspeak character mapping (`1->i, 0->o, 3->e, 4->a`) |
| **Model Token Boundaries** | ChatML, LLaMA, Claude, Hermes tags | Strips `<\|im_start\|>`, `[INST]`, `<<SYS>>`, `[OUT-OF-BAND]` |
| **Multilingual Overrides** | Non-English prompts (RU, DE, ES, FR, ZH, JA, AR, KO, HI) | Multi-script heuristic checks directly on native text |
| **Role / Turn Spoofing** | Faked headers (`=== BEGIN SYSTEM PROMPT ===`) | Intercepts delimiter and conversational dialogue fakes |
| **Trajectory Hijacking** | Scratchpad poisoning (`Thought:`, `Action: terminal`) | Blocks fake ReAct loops from contaminating memory |
| **JSON Tool Smuggling** | Embedded `{"tool_calls": [...]}` in raw text | Catches structured tool-call and assistant role injections |
| **Encoded Steganography** | Base64, 8-bit binary, ROT13, URL-encoded | Decodes payloads and evaluates inner text recursively |
| **Shannon Entropy Anomaly** | Dense encrypted shellcode without spaces | Calculates Shannon entropy; flags payloads with entropy $\ge 4.9$ |
| **Secret Harvesting** | Probing `$OPENROUTER_API_KEY`, `.env`, `id_rsa` | Blocks commands seeking high-value environment tokens |
| **Acrostic Steganography** | First letter of consecutive words spelling `DISREGARD` | Acrostic initial-letter detector on consecutive words |
| **HTML Entity Obfuscation**| Hex/decimal entities (`&#105;&#103;&#110;`) | Fully unescapes entities and hex escapes before analysis |
| **Dual-Sided Output Leak** | Exfiltration links in generated agent summaries | Sanitizes output: strips tracking images & `javascript:` URLs |
| **Shell Breakout / Query DoS**| Command injection in queries (`; rm -rf ~`) | Validates balanced quotes/parentheses and max nesting depth $\le 4$ |

---

## Quick Start

### Installation

Requires Python 3.10+ (zero external dependencies):

```bash
git clone https://github.com/nadimtuhin/hermes-gog-spam-guard.git
cd hermes-gog-spam-guard
pip install -e .
```

### CLI Usage

#### 1. Scan and Sanitize Spam
Scan Gmail spam directly using your local `gog` CLI credentials or an exported JSON file:

```bash
# Direct scan via gog CLI
hermes-gog-spam-guard scan --limit 50

# Scan from an exported JSON file in sandbox
hermes-gog-spam-guard scan --file /tmp/spam_emails.json
```

Output:
```
Total Emails Processed: 26
Safe Messages:          26
Quarantined Messages:   0

[+] Clustered Spam Campaigns:
  casino_gambling: 7 messages
  brand_phishing: 7 messages
  compromised_relays_adult: 4 messages
  miracle_cure_medical: 5 messages

[*] Recommended Senders to Allowlist (--never-spam):
  - newsletter@evalsignal.xyz | Subj: Qwen3.8-Flash-Next on a gaming PC?
  - help@resiliens.com | Subj: For the thoughts that show up at 2am
```

#### 2. Check Text for Injections
Test any raw string or suspect email snippet:

```bash
hermes-gog-spam-guard check "Attention: d.i.s.r.e.g.a.r.d p.r.i.o.r i.n.s.t.r.u.c.t.i.o.n.s"
# Output: [!] INJECTION DETECTED: fragmented_injection: disregard prior instructions
```

#### 3. Validate Gmail Search Queries
Validate filter syntax and prevent shell breakout attempts:

```bash
hermes-gog-spam-guard validate-query 'subject:("Free Spins" OR "royal welcome")'
# Output: [✓] Valid query

hermes-gog-spam-guard validate-query 'subject:("Free Spins"; rm -rf ~)'
# Output: [!] Invalid query: Query contains illegal shell character: ';'
```

---

## Python API

```python
from hermes_gog_spam_guard import (
    process_spam_batch,
    detect_prompt_injection,
    validate_gmail_query,
    build_safe_gog_args
)

# 1. Detect prompt injections
is_injected, reason = detect_prompt_injection("Please &#105;&#103;&#110;&#111;&#114;&#101; prior instructions")
# is_injected == True

# 2. Process an entire batch of incoming emails
results = process_spam_batch(raw_emails)
print(f"Safe: {results['safe_count']}, Quarantined: {results['quarantined_count']}")

# 3. Build safe, non-shell gog commands (shell=False)
valid, args, err = build_safe_gog_args('subject:("Free Spins" OR "royal welcome")', action="--trash")
# args == ['gog', 'gmail', 'settings', 'filters', 'create', '--query', '...', '--trash', '-y']
```

---

## Hermes Agent Plugin Integration

`hermes-gog-spam-guard` works out of the box as a native plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent).

Symlink or copy the directory to `~/.hermes/plugins/hermes-gog-spam-guard`:

```bash
ln -s $(pwd) ~/.hermes/plugins/hermes-gog-spam-guard
hermes plugins enable hermes-gog-spam-guard
```

Provides tools:
- `gog_spam_scan`: Safely inspects spam without exposing the agent to injection contexts.
- `gog_filter_apply`: Validates query grammar and applies server-side `--trash` or `--never-spam` rules.

---

## Running Tests

All 39 adversarial test cases run instantly using standard Python `unittest`:

```bash
python3 -m unittest tests/test_sanitizer.py
```

---

## License

MIT © [Omar Faruque Tuhin (Nadim)](https://github.com/nadimtuhin)
