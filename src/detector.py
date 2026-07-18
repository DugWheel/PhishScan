import base64
import json
import logging
import re
import time
from datetime import datetime, timezone
from email import message_from_bytes
from email.header import decode_header
from email.message import Message
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import dns.resolver
import requests
from bs4 import BeautifulSoup

log = logging.getLogger("PhishScan.Detector")

PROJECT_ROOT = Path(__file__).parent.parent


def _load_config() -> dict:
    config_path = PROJECT_ROOT / "config.json"
    if config_path.exists():
        return json.loads(config_path.read_text(encoding="utf-8"))
    return {}


_raw_config = _load_config()

CONFIG = {
    "virustotal_api_key": _raw_config.get("virustotal_api_key", ""),
    "urlscan_api_key": _raw_config.get("urlscan_api_key", ""),
    "risk_threshold": _raw_config.get("risk_threshold", 60),
    "redirect_timeout": _raw_config.get("redirect_timeout", 5),
    "whitelist_domains": _raw_config.get("whitelist_domains", []),
}

PHISHING_KEYWORDS = [
    "hemen tıklayın", "işlem size mi ait", "hesabınız askıya alındı",
    "acil", "doğrulayın", "kimliğinizi onaylayın", "şüpheli işlem",
    "son uyarı", "hesabınız kapatılacak", "ödeme bilgilerinizi güncelleyin",
    "güvenlik ihlali", "yetkisiz giriş", "hesabınızı koruyun",
    "verify your account", "unusual activity", "click immediately",
    "your account will be suspended", "confirm your identity",
    "unauthorized access", "security alert", "update payment",
]

URGENCY_PATTERNS = [
    r"\b(24|48|72)\s*saat\b",
    r"\bson\s+\d+\s+(saat|gün)\b",
    r"\bexpires?\s+in\b",
]

KNOWN_ESP_DOMAINS = [
    "mcsv.net", "mcdlv.net", "mailchimp.com", "mandrillapp.com",
    "sendgrid.net", "sendgrid.com", "amazonses.com", "sparkpostmail.com",
    "mailgun.org", "postmarkapp.com", "campaign-archive.com",
]

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "ref", "referrer", "source",
    "mc_cid", "mc_eid", "yclid",
}

QUARANTINE_THRESHOLD_DEFAULT = 60
WARN_THRESHOLD = 35
GATE_CLEAN_BELOW = 15
GATE_CERTAIN_ABOVE = 80
MAX_URLS_PER_EMAIL = 5
VT_CACHE_TTL_SECONDS = 86_400


def parse_email(raw_bytes: bytes) -> Message:
    return message_from_bytes(raw_bytes)


def read_header(msg: Message, name: str, default: str = "") -> str:
    raw_value = msg.get(name, default)
    if raw_value is None:
        return default

    raw_str = str(raw_value)
    try:
        decoded_chunks = decode_header(raw_str)
        return "".join(
            chunk.decode(encoding or "utf-8", errors="replace")
            if isinstance(chunk, bytes) else chunk
            for chunk, encoding in decoded_chunks
        )
    except Exception:
        return raw_str


def extract_domain(email_header_value: str) -> str:
    match = re.search(r"@([\w.\-]+)", email_header_value)
    return match.group(1).lower() if match else ""


def extract_email_body(raw_bytes: bytes) -> str:
    msg = parse_email(raw_bytes)
    body = ""

    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        payload = part.get_payload(decode=True)
        if not payload:
            continue

        text = payload.decode(errors="ignore")
        content_type = part.get_content_type()

        if content_type == "text/html":
            return BeautifulSoup(text, "html.parser").get_text(separator=" ").lower()
        if content_type == "text/plain" and not body:
            body = text

    return body.lower()


def check_spf(sender_domain: str) -> dict:
    try:
        for record in dns.resolver.resolve(sender_domain, "TXT"):
            if record.to_text().strip('"').startswith("v=spf1"):
                return {"pass": True, "risk": 0}
    except Exception as exc:
        log.warning(f"SPF sorgusu başarısız ({sender_domain}): {exc}")
    return {"pass": False, "risk": 30}


def check_dkim(msg: Message) -> dict:
    has_signature = bool(msg.get("DKIM-Signature", ""))
    return {"pass": has_signature, "risk": 0 if has_signature else 25}


def check_dmarc(sender_domain: str) -> dict:
    try:
        for record in dns.resolver.resolve(f"_dmarc.{sender_domain}", "TXT"):
            txt = record.to_text().strip('"')
            if "v=DMARC1" not in txt:
                continue
            if "p=reject" in txt:
                return {"pass": True, "policy": "reject", "risk": 0}
            if "p=quarantine" in txt:
                return {"pass": True, "policy": "quarantine", "risk": 0}
            return {"pass": True, "policy": "none", "risk": 10}
    except Exception as exc:
        log.warning(f"DMARC sorgusu başarısız ({sender_domain}): {exc}")
    return {"pass": False, "policy": "none", "risk": 20}


def check_return_path_mismatch(sender_domain: str, return_path_header: str) -> int:
    return_path = return_path_header.strip("<>")
    if not (sender_domain and return_path and "@" in return_path):
        return 0

    return_path_domain = return_path.split("@")[-1].lower()
    domains_match = (
        sender_domain.lower() in return_path_domain
        or return_path_domain in sender_domain.lower()
    )
    if domains_match:
        return 0

    is_known_esp = any(esp in return_path_domain for esp in KNOWN_ESP_DOMAINS)
    if is_known_esp:
        log.debug(f"Return-Path bilinen ESP'ye ait, güvenli: {return_path_domain}")
        return 0

    log.info(f"Return-Path uyuşmazlığı: From={sender_domain} vs Return-Path={return_path_domain}")
    return 20


def analyze_headers(raw_bytes: bytes) -> dict:
    msg = parse_email(raw_bytes)
    sender_domain = extract_domain(read_header(msg, "From"))

    spf = check_spf(sender_domain)
    dkim = check_dkim(msg)
    dmarc = check_dmarc(sender_domain)
    return_path_risk = check_return_path_mismatch(
        sender_domain, read_header(msg, "Return-Path")
    )

    total_risk = spf["risk"] + dkim["risk"] + dmarc["risk"] + return_path_risk

    return {
        "sender_domain": sender_domain,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "return_path_risk": return_path_risk,
        "header_risk_score": min(total_risk, 75),
    }


def analyze_content(raw_bytes: bytes) -> dict:
    body = extract_email_body(raw_bytes)

    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in body]
    urgency_hits = sum(1 for pattern in URGENCY_PATTERNS if re.search(pattern, body))

    raw_score = len(found_keywords) * 10 + urgency_hits * 5

    return {
        "found_keywords": found_keywords,
        "urgency_pattern_hits": urgency_hits,
        "content_risk_score": min(raw_score, 40),
    }


_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")


def extract_urls(raw_bytes: bytes) -> list[str]:
    msg = parse_email(raw_bytes)
    urls: list[str] = []

    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        text = payload.decode(errors="ignore")

        if part.get_content_type() == "text/html":
            soup = BeautifulSoup(text, "html.parser")
            for tag in soup.find_all(["a", "button", "form"]):
                href = tag.get("href") or tag.get("action", "")
                if href.startswith("http"):
                    urls.append(href)

        urls.extend(_URL_PATTERN.findall(text))

    return list(set(urls))


def resolve_redirects(url: str) -> str:
    try:
        response = requests.head(
            url,
            allow_redirects=True,
            timeout=CONFIG["redirect_timeout"],
            headers={"User-Agent": "Mozilla/5.0"},
        )
        return response.url
    except Exception as exc:
        log.warning(f"Redirect çözümlenemedi ({url}): {exc}")
        return url


class VirusTotalCache:
    def __init__(self):
        self._cache_file = PROJECT_ROOT / "data" / "vt_cache.json"
        self._cache_file.parent.mkdir(parents=True, exist_ok=True)
        self._entries = self._load_from_disk()

    def _load_from_disk(self) -> dict:
        if not self._cache_file.exists():
            return {}
        try:
            return json.loads(self._cache_file.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_to_disk(self) -> None:
        try:
            self._cache_file.write_text(
                json.dumps(self._entries, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            log.warning(f"VT cache kaydedilemedi: {exc}")

    def get(self, cache_key: str) -> dict | None:
        entry = self._entries.get(cache_key)
        if entry is None:
            return None
        age_seconds = time.time() - entry.get("cached_at", 0)
        if age_seconds > VT_CACHE_TTL_SECONDS:
            return None
        return entry["result"]

    def set(self, cache_key: str, result: dict) -> None:
        self._entries[cache_key] = {"cached_at": time.time(), "result": result}
        self._save_to_disk()


_vt_cache = VirusTotalCache()


def normalize_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        clean_params = {
            key: value for key, value in query_params.items()
            if key.lower() not in TRACKING_PARAMS
        }
        clean_query = urlencode(clean_params, doseq=True)
        normalized = urlunparse(parsed._replace(query=clean_query, fragment=""))
        return normalized.rstrip("/")
    except Exception:
        return url


def check_virustotal(url: str) -> dict:
    api_key = CONFIG["virustotal_api_key"].strip()
    if not api_key:
        return {"malicious_engines": 0, "suspicious_engines": 0, "vt_risk": 0}

    normalized_url = normalize_url(url)
    cached_result = _vt_cache.get(normalized_url)
    if cached_result:
        log.info(f"VT cache'den döndü: {normalized_url[:60]}")
        return cached_result

    url_id = base64.urlsafe_b64encode(normalized_url.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        response = requests.get(
            endpoint, headers={"x-apikey": api_key}, timeout=10
        )

        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            result = {
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "vt_risk": min(malicious * 15 + suspicious * 5, 50),
            }
            _vt_cache.set(normalized_url, result)
            log.info(f"VT API sorgulandı: {normalized_url[:60]} → {malicious} malicious")
            return result

        if response.status_code == 404:
            result = {"malicious_engines": 0, "suspicious_engines": 0, "vt_risk": 10}
            _vt_cache.set(normalized_url, result)
            log.info(f"VT bu URL'yi tanımıyor (404): {normalized_url[:60]}")
            return result

    except Exception as exc:
        log.warning(f"VirusTotal hatası: {exc}")

    return {"malicious_engines": 0, "suspicious_engines": 0, "vt_risk": 0}


def check_urlscan(url: str) -> dict:
    api_key = CONFIG["urlscan_api_key"].strip()
    if not api_key:
        return {"malicious": False, "score": 0, "urlscan_risk": 0}

    try:
        submit_response = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={"API-Key": api_key, "Content-Type": "application/json"},
            json={"url": url, "visibility": "private"},
            timeout=10,
        )
        if submit_response.status_code != 200:
            return {"malicious": False, "score": 0, "urlscan_risk": 0}

        scan_id = submit_response.json().get("uuid", "")
        time.sleep(15)

        result = requests.get(
            f"https://urlscan.io/api/v1/result/{scan_id}/", timeout=10
        ).json()
        verdict = result.get("verdicts", {}).get("overall", {})

        return {
            "malicious": verdict.get("malicious", False),
            "score": verdict.get("score", 0),
            "urlscan_risk": 40 if verdict.get("malicious") else 0,
        }
    except Exception as exc:
        log.warning(f"URLScan hatası: {exc}")
        return {"malicious": False, "score": 0, "urlscan_risk": 0}


def analyze_urls(raw_bytes: bytes, pre_score: int) -> dict:
    urls = extract_urls(raw_bytes)

    if pre_score < GATE_CLEAN_BELOW:
        return {
            "total_urls_found": len(urls), "analyzed_urls": [],
            "url_risk_score": 0, "gate_tier": "CLEAN",
        }

    if pre_score > GATE_CERTAIN_ABOVE:
        return {
            "total_urls_found": len(urls), "analyzed_urls": [],
            "url_risk_score": 0, "gate_tier": "CERTAIN",
        }

    log.info(f"3-Tier Gate: GREY (pre_score={pre_score}) — URL API sorgulanıyor.")

    analyzed = []
    highest_risk = 0

    for url in urls[:MAX_URLS_PER_EMAIL]:
        final_url = resolve_redirects(url)
        vt_result = check_virustotal(final_url)
        urlscan_result = check_urlscan(final_url)
        url_risk = max(vt_result["vt_risk"], urlscan_result["urlscan_risk"])
        highest_risk = max(highest_risk, url_risk)

        analyzed.append({
            "original_url": url,
            "final_url": final_url,
            "virustotal": vt_result,
            "urlscan": urlscan_result,
            "url_risk": url_risk,
        })

    return {
        "total_urls_found": len(urls),
        "analyzed_urls": analyzed,
        "url_risk_score": min(highest_risk, 50),
        "gate_tier": "GREY",
    }


def score_to_verdict(score: int) -> tuple[str, str]:
    threshold = CONFIG.get("risk_threshold", QUARANTINE_THRESHOLD_DEFAULT)

    if score >= threshold:
        return "QUARANTINE", "E-posta karantinaya alındı ve kullanıcı uyarıldı."
    if score >= WARN_THRESHOLD:
        return "WARN", "E-posta uyarı etiketiyle teslim edildi."
    return "PASS", "E-posta temiz, teslim edildi."


def calculate_risk(header_result: dict, content_result: dict, url_result: dict) -> dict:
    header_score = header_result.get("header_risk_score", 0) * 0.5
    content_score = content_result.get("content_risk_score", 0) * 0.5
    url_score = url_result.get("url_risk_score", 0) * 1.0

    final_score = min(round(header_score + content_score + url_score), 100)
    verdict, action = score_to_verdict(final_score)

    return {
        "final_risk_score": final_score,
        "verdict": verdict,
        "action": action,
        "breakdown": {
            "header": round(header_score),
            "content": round(content_score),
            "url": round(url_score),
        },
    }


def is_whitelisted(sender_domain: str) -> bool:
    if not sender_domain:
        return False

    whitelist = [d.lower().strip() for d in CONFIG.get("whitelist_domains", [])]
    return any(
        sender_domain == trusted or sender_domain.endswith(f".{trusted}")
        for trusted in whitelist
    )


def get_nlp_second_opinion(raw_bytes: bytes, current_score: int) -> dict:
    fallback = {
        "nlp_provider": "disabled", "nlp_boost": 0,
        "nlp_label": "N/A", "applied": False,
    }
    try:
        from nlp_engine import refine
        body_text = extract_email_body(raw_bytes)
        return refine(body_text=body_text, current_score=current_score)
    except ImportError:
        return fallback
    except Exception as exc:
        log.warning(f"NLP çalıştırılamadı: {exc}")
        return fallback


def analyze_email(raw_bytes: bytes) -> dict:
    msg = parse_email(raw_bytes)
    sender_domain = extract_domain(read_header(msg, "From"))

    if is_whitelisted(sender_domain):
        log.info(f"[SAFE/Whitelist] {sender_domain} güvenilir listede — analiz atlandı.")
        return {
            "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "verdict": "SAFE",
            "action": f"Güvenilir gönderen ({sender_domain}) — analiz atlandı.",
            "risk_score": 0,
            "breakdown": {"header": 0, "content": 0, "url": 0},
            "details": {"whitelist_hit": True, "sender_domain": sender_domain},
        }

    log.info(f"Analiz başlıyor… (gönderen: {sender_domain or 'bilinmiyor'})")

    header_result = analyze_headers(raw_bytes)
    content_result = analyze_content(raw_bytes)

    pre_score = min(round(
        header_result["header_risk_score"] * 0.5
        + content_result["content_risk_score"] * 0.5
    ), 100)

    url_result = analyze_urls(raw_bytes, pre_score=pre_score)
    decision = calculate_risk(header_result, content_result, url_result)

    final_score = decision["final_risk_score"]
    final_verdict = decision["verdict"]
    final_action = decision["action"]

    nlp_result = get_nlp_second_opinion(raw_bytes, final_score)
    nlp_boost = nlp_result.get("nlp_boost", 0)

    if nlp_result.get("applied") and nlp_boost != 0:
        boosted_score = max(0, min(100, final_score + nlp_boost))
        boosted_verdict, boosted_action = score_to_verdict(boosted_score)
        log.info(
            f"NLP boost uygulandı: {final_score} → {boosted_score} "
            f"({final_verdict} → {boosted_verdict})"
        )
        final_score, final_verdict, final_action = boosted_score, boosted_verdict, boosted_action

    log.info(f"Sonuç → {final_verdict} (Skor: {final_score}/100)")

    return {
        "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "verdict": final_verdict,
        "action": final_action,
        "risk_score": final_score,
        "breakdown": decision["breakdown"],
        "nlp": nlp_result,
        "details": {
            "header": header_result,
            "content": content_result,
            "urls": url_result,
        },
    }


if __name__ == "__main__":
    import sys

    eml_path = sys.argv[1] if len(sys.argv) > 1 else "sample.eml"
    with open(eml_path, "rb") as f:
        report = analyze_email(f.read())
    print(json.dumps(report, ensure_ascii=False, indent=2))
