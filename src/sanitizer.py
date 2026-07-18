import re
import logging

log = logging.getLogger("PhishScan.Sanitizer")

_RULES: list[tuple[str, re.Pattern, str]] = [
    (
        "URL",
        re.compile(
            r"https?://[^\s\"'<>\]\)]+|ftp://[^\s\"'<>\]\)]+",
            re.IGNORECASE,
        ),
        "[REDACTED_URL]",
    ),
    (
        "EMAIL",
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE),
        "[REDACTED_EMAIL]",
    ),
    (
        "IPV4",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        "[REDACTED_IP]",
    ),
    (
        "IPV6",
        re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b",
            re.IGNORECASE,
        ),
        "[REDACTED_IP]",
    ),
    (
        "TCKN",
        re.compile(r"\b[1-9]\d{10}\b"),
        "[REDACTED_TCKN]",
    ),
    (
        "IBAN",
        re.compile(r"\bTR\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{2}\b", re.IGNORECASE),
        "[REDACTED_IBAN]",
    ),
    (
        "CARD",
        re.compile(r"\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b"),
        "[REDACTED_CARD]",
    ),
    (
        "PHONE_TR",
        re.compile(
            r"(?:\+90|0090|0)[\s\-\.]?(?:\(?\d{3}\)?)[\s\-\.]?\d{3}[\s\-\.]?\d{2}[\s\-\.]?\d{2}"
            r"|\b5\d{2}[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b"
        ),
        "[REDACTED_PHONE]",
    ),
    (
        "PLATE_TR",
        re.compile(r"\b\d{2}\s?[A-Z]{1,3}\s?\d{2,4}\b", re.IGNORECASE),
        "[REDACTED_PLATE]",
    ),
    (
        "OTP",
        re.compile(r"(?<!\d)\d{4,8}(?!\d)"),
        "[REDACTED_CODE]",
    ),
]


def sanitize(text: str, rules: list[str] | None = None) -> tuple[str, dict]:
    if not text:
        return text, {}

    stats: dict[str, int] = {}
    result = text

    active_rules = _RULES
    if rules is not None:
        rule_set = set(rules)
        active_rules = [(n, p, r) for n, p, r in _RULES if n in rule_set]

    for name, pattern, replacement in active_rules:
        matches = pattern.findall(result)
        if matches:
            stats[name] = len(matches)
            result = pattern.sub(replacement, result)

    if stats:
        log.debug(f"Sanitizasyon tamamlandı: {stats}")

    return result, stats


def sanitize_for_api(
    text: str,
    max_chars: int = 200,
    extra_rules: list[str] | None = None,
) -> tuple[str, dict]:
    sanitized, stats = sanitize(text, rules=extra_rules)

    truncated = False
    if len(sanitized) > max_chars:
        cut = sanitized[:max_chars].rsplit(" ", 1)[0]
        sanitized = cut + " […kırpıldı]"
        truncated = True

    return sanitized, {"sanitize_stats": stats, "truncated": truncated}


def mask_email_body(raw_text: str) -> str:
    masked, _ = sanitize(raw_text)
    return masked
