import asyncio
import json
import logging
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from detector import analyze_email
from gmail_integration import (
    add_warning_label,
    fetch_unread_emails,
    get_gmail_service,
    mark_as_scanned,
    quarantine_email,
    send_telegram_alert,
    update_telegram_stats,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("phishscan.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("PhishScan.Main")

CONFIG_PATH = Path(__file__).parent.parent / "config.json"
TELEGRAM_TOKEN_PLACEHOLDER = "TELEGRAM_BOT_TOKEN_BURAYA"



_fallback_stop_event = threading.Event()


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        log.error(f"config.json bulunamadı: {CONFIG_PATH}")
        sys.exit(1)
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def is_telegram_enabled(config: dict) -> bool:
    token = config.get("telegram_bot_token", "").strip()
    return bool(token) and token != TELEGRAM_TOKEN_PLACEHOLDER


def get_telegram_state() -> dict | None:
    try:
        from telegram_controller import system_state
        return system_state
    except ImportError:
        return None


def run_telegram_bot() -> None:
    try:
        from telegram_controller import start_bot_async
    except ImportError:
        log.warning(
            "python-telegram-bot kurulu değil. Telegram desteği olmadan "
            "devam ediliyor. Kurmak için: pip install python-telegram-bot>=20.7"
        )
        return

    log.info("Telegram thread başlatılıyor…")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(start_bot_async())
    except Exception as exc:
        log.error(f"Telegram thread beklenmedik hatayla durdu: {exc}", exc_info=True)
    finally:
        loop.close()


def _log_scan_result(email: dict, report: dict) -> None:
    verdict = report.get("verdict", "?")
    score = report.get("risk_score", 0)
    subject = email.get("subject", "?")[:55]
    sender = email.get("sender", "?")
    
    log.info(f"[{verdict}] {subject}")
    log.info(f"   Skor: {score}/100 | Gönderen: {sender}")

    nlp = report.get("nlp", {})
    if nlp.get("applied"):
        boost = nlp.get("nlp_boost", 0)
        boost_str = f"{boost:+d}" if boost != 0 else "±0"
        log.info(f"   NLP : {nlp.get('nlp_label', 'N/A')} (boost {boost_str})")

    log.info("   " + "─" * 52)


def _apply_gmail_action(service, email: dict, report: dict, config: dict) -> None:
    verdict = report["verdict"]

    if verdict == "QUARANTINE":
        quarantine_email(service, email["id"])
    elif verdict == "WARN":
        label_id = config.get("warning_label_id", "").strip()
        if label_id:
            add_warning_label(service, email["id"], label_id)


def run_auto_scan(config: dict, fallback_stop_event: threading.Event) -> None:
    if not config.get("auto_start_scan", True):
        log.info("Otomatik tarama devre dışı (auto_start_scan: false).")
        return

    service = get_gmail_service()
    interval_seconds = config.get("scan_interval_seconds", 300)
    max_results = config.get("scan_max_results", 30)

    # Telegram durumunu DÖNGÜ DIŞINDA bir kez al 
    telegram_state = get_telegram_state()
    if telegram_state is not None:
        stop_event = telegram_state["stop_event"]
        telegram_state["active"] = True
        telegram_state["start_time"] = datetime.now(timezone.utc)
        stop_event.clear()
        log.info("Tarama döngüsü Telegram stop_event'ine bağlandı.")
    else:
        stop_event = fallback_stop_event
        log.info("Tarama döngüsü yedek stop_event'e bağlandı (Telegram yok).")

    log.info("Tarama döngüsü başlatıldı.")

    while True:
        
        if fallback_stop_event.is_set():
            break

        
        if stop_event.is_set():
            time.sleep(5)
            continue

        try:
            emails = fetch_unread_emails(service, max_results=max_results)

            for email in emails:
                if stop_event.is_set() or fallback_stop_event.is_set():
                    break

                report = analyze_email(email["raw"])
                report["subject"] = email["subject"]
                report["sender"] = email["sender"]

                try:
                    _apply_gmail_action(service, email, report, config)
                except Exception as g_exc:
                    
                    log.warning(f"Gmail aksiyonu başarısız (Etiket ID'nizi kontrol edin): {g_exc}")

                
                mark_as_scanned(email["id"])
                _log_scan_result(email, report)

                send_telegram_alert(report, config)
                update_telegram_stats(report)

        except Exception as exc:
            log.error(f"Tarama döngüsü hatası: {exc}")

        
        stop_event.wait(timeout=interval_seconds)


def handle_shutdown(signum, frame) -> None:
    log.info("Kapatma sinyali alındı. Sistem durduruluyor…")
    _fallback_stop_event.set()

    telegram_state = get_telegram_state()
    if telegram_state is not None:
        telegram_state["stop_event"].set()
        telegram_state["active"] = False
        telegram_state["bot_shutdown"].set()

    sys.exit(0)


def main() -> None:
    log.info("=" * 55)
    log.info("  PhishScan başlatılıyor…")
    log.info("=" * 55)

    config = load_config()

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    if is_telegram_enabled(config):
        threading.Thread(target=run_telegram_bot, name="TelegramBot", daemon=True).start()
        log.info(" Thread-1 Telegram Botu başlatıldı.")
        time.sleep(2)
    else:
        log.info(" Telegram token tanımlı değil — yalnızca log modu aktif.")

    threading.Thread(
        target=run_auto_scan,
        args=(config, _fallback_stop_event),
        name="GmailScanner",
        daemon=True,
    ).start()
    log.info(" Thread-2 (Gmail Tarayıcı) başlatıldı.")

    log.info("─" * 55)
    log.info("Sistem çalışıyor. Durdurmak için Ctrl+C.")
    if is_telegram_enabled(config):
        log.info("Telegram'dan /durum yazarak sistemi izleyebilirsiniz.")
    else:
        log.info("Tespitler phishscan.log dosyasına yazılıyor.")
    log.info("─" * 55)

    while not _fallback_stop_event.is_set():
        time.sleep(60)


if __name__ == "__main__":
    main()
