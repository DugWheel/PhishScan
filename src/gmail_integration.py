import base64
import json
import logging
import os
from email import message_from_bytes
from email.header import decode_header
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

log = logging.getLogger("PhishScan.Gmail")

PROJECT_ROOT = Path(__file__).parent.parent
CREDENTIALS_FILE = str(PROJECT_ROOT / "credentials.json")
TOKEN_FILE = str(PROJECT_ROOT / "token.json")
SCANNED_IDS_FILE = PROJECT_ROOT / "data" / "scanned_ids.json"

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]

MAX_STORED_SCANNED_IDS = 5000
TELEGRAM_TOKEN_PLACEHOLDER = "TELEGRAM_BOT_TOKEN_BURAYA"


def _load_config() -> dict:
    config_path = PROJECT_ROOT / "config.json"
    with open(config_path, encoding="utf-8") as f:
        return json.load(f)


def get_gmail_service():
    credentials = None
    if os.path.exists(TOKEN_FILE):
        credentials = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not credentials or not credentials.valid:
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            credentials = flow.run_local_server(port=0)
        with open(TOKEN_FILE, "w") as f:
            f.write(credentials.to_json())

    return build("gmail", "v1", credentials=credentials)


def _load_scanned_ids() -> set:
    if not SCANNED_IDS_FILE.exists():
        return set()
    try:
        return set(json.loads(SCANNED_IDS_FILE.read_text(encoding="utf-8")))
    except Exception:
        return set()


def _save_scanned_ids(scanned_ids: set) -> None:
    SCANNED_IDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        limited_ids = list(scanned_ids)[-MAX_STORED_SCANNED_IDS:]
        SCANNED_IDS_FILE.write_text(json.dumps(limited_ids), encoding="utf-8")
    except Exception as exc:
        log.warning(f"scanned_ids kaydedilemedi: {exc}")


_scanned_ids: set = _load_scanned_ids()


def mark_as_scanned(message_id: str) -> None:
    _scanned_ids.add(message_id)
    _save_scanned_ids(_scanned_ids)


def _decode_email_header(value: str) -> str:
    if not value:
        return ""
    
    decoded_chunks = decode_header(value)
    result = []
    
    for chunk, encoding in decoded_chunks:
        if isinstance(chunk, bytes):
            safe_encoding = encoding if encoding else "utf-8"
            try:
                result.append(chunk.decode(safe_encoding, errors="replace"))
            except LookupError:
                
                result.append(chunk.decode("utf-8", errors="replace"))
            except Exception:
               
                result.append(str(chunk))
        else:
            result.append(chunk)
            
    return "".join(result)

def fetch_unread_emails(service, max_results: int = 20) -> list[dict]:
    response = (
        service.users().messages()
        .list(userId="me", labelIds=["INBOX", "UNREAD"], maxResults=max_results)
        .execute()
    )
    message_refs = response.get("messages", [])

    emails = []
    skipped_count = 0

    for ref in message_refs:
        message_id = ref["id"]
        if message_id in _scanned_ids:
            skipped_count += 1
            continue

        message_data = (
            service.users().messages()
            .get(userId="me", id=message_id, format="raw")
            .execute()
        )
        raw_bytes = base64.urlsafe_b64decode(message_data["raw"])
        parsed = message_from_bytes(raw_bytes)

        emails.append({
            "id": message_id,
            "raw": raw_bytes,
            "subject": _decode_email_header(parsed.get("Subject", "Konu yok")),
            "sender": _decode_email_header(parsed.get("From", "Bilinmiyor")),
        })

    if len(message_refs) >= max_results and skipped_count > 0:
        log.warning(
            f"UNREAD mail sayısı ({len(message_refs)}) max_results'a "
            f"({max_results}) ulaştı/aştı. {skipped_count} mail zaten "
            f"taranmıştı, {len(emails)} yeni mail işlendi. Bazı eski "
            f"UNREAD mailler görülmemiş olabilir — max_results'ı artırın."
        )

    return emails


def quarantine_email(service, message_id: str) -> None:
    try:
        service.users().messages().modify(
            userId="me", id=message_id,
            body={"removeLabelIds": ["INBOX", "UNREAD"], "addLabelIds": ["SPAM"]},
        ).execute()
        log.info(f"[KARANTINA] {message_id} başarıyla Spam klasörüne taşındı.")
    except Exception as exc:
        log.error(f"[KARANTINA HATASI] {message_id} Spam'a taşınamadı: {exc}")

def add_warning_label(service, message_id: str, label_id: str) -> None:
    if not label_id:
        return
    service.users().messages().modify(
        userId="me", id=message_id, body={"addLabelIds": [label_id]},
    ).execute()
    log.info(f"[UYARI] {message_id}")


def _telegram_credentials(config: dict) -> tuple[str, int] | None:
    token = config.get("telegram_bot_token", "").strip()
    chat_id = config.get("telegram_allowed_user_id", 0)

    if not token or token == TELEGRAM_TOKEN_PLACEHOLDER or not chat_id:
        return None
    return token, chat_id


def send_telegram_alert(report: dict, config: dict) -> None:
    if report.get("verdict") != "QUARANTINE":
        return

    credentials = _telegram_credentials(config)
    if credentials is None:
        return
    token, chat_id = credentials

    try:
        from telegram_controller import send_threat_alert_sync
        send_threat_alert_sync(
            record={
                "subject": report.get("subject", "?"),
                "sender": report.get("sender", "?"),
                "risk_score": report.get("risk_score", 0),
                "verdict": report.get("verdict", "?"),
                "action": report.get("action", "?"),
                "detected_at": report.get("analyzed_at", "?"),
            },
            bot_token=token,
            chat_id=chat_id,
        )
    except ImportError:
        log.debug("telegram_controller bulunamadı; bildirim atlandı.")
    except Exception as exc:
        log.warning(f"Telegram bildirimi gönderilemedi (sistem devam ediyor): {exc}")


def update_telegram_stats(report: dict) -> None:
    try:
        from telegram_controller import add_threat_record
        add_threat_record({
            "subject": report.get("subject", "?"),
            "sender": report.get("sender", "?"),
            "risk_score": report.get("risk_score", 0),
            "verdict": report.get("verdict", "?"),
            "action": report.get("action", "?"),
            "detected_at": report.get("analyzed_at", "?"),
        })
    except ImportError:
        pass
    except Exception as exc:
        log.debug(f"Durum güncellenemedi: {exc}")


def run_gmail_scan() -> list[dict]:
    from detector import analyze_email

    config = _load_config()
    service = get_gmail_service()
    emails = fetch_unread_emails(service)
    log.info(f"{len(emails)} e-posta taranıyor…")

    reports = []
    for email in emails:
        report = analyze_email(email["raw"])
        report["subject"] = email["subject"]
        report["sender"] = email["sender"]
        report["message_id"] = email["id"]

        verdict = report["verdict"]
        if verdict == "QUARANTINE":
            quarantine_email(service, email["id"])
        elif verdict == "WARN":
            add_warning_label(service, email["id"], config.get("warning_label_id", ""))

        mark_as_scanned(email["id"])
        send_telegram_alert(report, config)
        update_telegram_stats(report)

        reports.append(report)

    return reports


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_gmail_scan()
