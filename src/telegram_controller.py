import json
import logging
import threading
import html
from datetime import datetime, timezone
from pathlib import Path

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

log = logging.getLogger("PhishScan.TelegramBot")

PROJECT_ROOT = Path(__file__).parent.parent
MAX_RECENT_THREATS = 10
THREATS_SHOWN_IN_COMMAND = 3


def _load_config() -> dict:
    config_path = PROJECT_ROOT / "config.json"
    with open(config_path, encoding="utf-8") as f:
        return json.load(f)


_config = _load_config()
TELEGRAM_TOKEN = _config.get("telegram_bot_token", "")
ALLOWED_USER_ID = _config.get("telegram_allowed_user_id", 0)

_lock = threading.Lock()

system_state = {
    "active": False,
    "total_scanned": 0,
    "total_blocked": 0,
    "start_time": None,
    "recent_threats": [],
    "stop_event": threading.Event(),
    "bot_shutdown": threading.Event(),
}


def _is_authorized(update: Update) -> bool:
    return update.effective_user.id == ALLOWED_USER_ID


async def _reject_unauthorized(update: Update) -> None:
    await update.message.reply_text("⛔ Bu botu kullanma yetkiniz yok.")


def add_threat_record(report: dict) -> None:
    with _lock:
        system_state["total_scanned"] += 1

        if report.get("verdict") == "QUARANTINE":
            system_state["total_blocked"] += 1
            system_state["recent_threats"].append(report)
            if len(system_state["recent_threats"]) > MAX_RECENT_THREATS:
                system_state["recent_threats"].pop(0)


def _format_uptime() -> str:
    start_time = system_state["start_time"]
    if not start_time:
        return "Henüz başlatılmadı"

    elapsed = datetime.now(timezone.utc) - start_time
    hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}s {minutes}dk {seconds}sn"


async def cmd_yardim(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_authorized(update):
        await _reject_unauthorized(update)
        return

    text = (
        "🛡️ <b>PhishScan — Komut Listesi</b>\n\n"
        "<code>/baslat</code>        → Taramayı başlat\n"
        "<code>/durdur</code>        → Taramayı durdur\n"
        "<code>/durum</code>         → Sistem durumu ve istatistik\n"
        "<code>/son_tehditler</code> → Son 3 karantina kaydı\n"
        "<code>/yardim</code>        → Bu mesaj\n"
    )
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_durum(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_authorized(update):
        await _reject_unauthorized(update)
        return

    with _lock:
        is_active = system_state["active"]
        total_scanned = system_state["total_scanned"]
        total_blocked = system_state["total_blocked"]

    uptime = _format_uptime()
    status_label = "🟢 Aktif" if is_active else "🔴 Durduruldu"
    block_rate = (
        f"{(total_blocked / total_scanned * 100):.1f}%"
        if total_scanned > 0 else "—"
    )

    text = (
        f"📊 <b>PhishScan Sistem Durumu</b>\n\n"
        f"Durum          : {status_label}\n"
        f"Çalışma Süresi : {uptime}\n"
        f"─────────────────────\n"
        f"Taranan E-posta : {total_scanned}\n"
        f"Engellenen      : {total_blocked}\n"
        f"Engelleme Oranı : {block_rate}\n"
    )
    await update.message.reply_text(text, parse_mode="HTML")


async def cmd_son_tehditler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_authorized(update):
        await _reject_unauthorized(update)
        return

    with _lock:
        recent = list(system_state["recent_threats"])

    if not recent:
        await update.message.reply_text("✅ Henüz kayıtlı tehdit yok.")
        return

    last_threats = recent[-THREATS_SHOWN_IN_COMMAND:][::-1]
    lines = ["🚨 <b>Son Tehditler</b>\n"]

    for index, threat in enumerate(last_threats, 1):
        detected_at = threat.get("detected_at", "?")[:19].replace("T", " ")
        # Dışarıdan gelen veriyi HTML tag'i zannedip çökmemesi için html.escape() kullanıyoruz
        subject_safe = html.escape(threat.get('subject', 'Bilinmiyor')[:50])
        sender_safe = html.escape(threat.get('sender', '?'))
        
        lines.append(
            f"🔴 <b>#{index}</b>\n"
            f"  Konu    : <code>{subject_safe}</code>\n"
            f"  Gönderen: <code>{sender_safe}</code>\n"
            f"  Skor    : <code>{threat.get('risk_score', '?')}/100</code>\n"
            f"  Aksiyon : {threat.get('action', '?')}\n"
            f"  Zaman   : {detected_at}\n"
        )

    await update.message.reply_text("\n".join(lines), parse_mode="HTML")


async def cmd_baslat(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_authorized(update):
        await _reject_unauthorized(update)
        return

    with _lock:
        if system_state["active"]:
            await update.message.reply_text(" Sistem zaten çalışıyor.")
            return
        system_state["active"] = True
        if system_state["start_time"] is None:
            system_state["start_time"] = datetime.now(timezone.utc)
        system_state["stop_event"].clear()

    await update.message.reply_text(
        " Tarama devam ettirildi.\n/durum ile izleyebilirsiniz."
    )


async def cmd_durdur(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not _is_authorized(update):
        await _reject_unauthorized(update)
        return

    with _lock:
        if not system_state["active"]:
            await update.message.reply_text(" Sistem zaten durdurulmuş.")
            return
        system_state["stop_event"].set()
        system_state["active"] = False

    await update.message.reply_text(
        "🛑 Tarama durduruldu.\n"
        "Mevcut tarama tamamlandıktan sonra duracak. /baslat ile devam edebilirsiniz."
    )


def send_threat_alert_sync(record: dict, bot_token: str, chat_id: int) -> None:
    import requests

    subject_safe = html.escape(record.get("subject", "?")[:60])
    sender_safe = html.escape(record.get("sender", "?"))
    risk_score = record.get("risk_score", "?")
    action = record.get("action", "?")
    detected_at = record.get("detected_at", "?")[:19].replace("T", " ")

    text = (
        f"🚨 <b>[DİKKAT] Oltalama Engellendi!</b>\n\n"
        f"📧 <b>Konu</b> : <code>{subject_safe}</code>\n"
        f"👤 <b>Gönderen</b> : <code>{sender_safe}</code>\n"
        f"🎯 <b>Risk Skoru</b>: <code>{risk_score}/100</code>\n"
        f"🔒 <b>Aksiyon</b> : {action}\n"
        f"🕐 <b>Zaman</b> : {detected_at} UTC\n"
    )

    try:
        requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
            timeout=10,
        )
    except Exception as exc:
        log.error(f"Telegram bildirimi gönderilemedi: {exc}")


def start_bot() -> None:
    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(start_bot_async())
    finally:
        loop.close()


async def start_bot_async() -> None:
    if not TELEGRAM_TOKEN:
        log.error("Telegram bot token bulunamadı. config.json dosyasını kontrol edin.")
        return

    app = Application.builder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("yardim", cmd_yardim))
    app.add_handler(CommandHandler("durum", cmd_durum))
    app.add_handler(CommandHandler("son_tehditler", cmd_son_tehditler))
    app.add_handler(CommandHandler("baslat", cmd_baslat))
    app.add_handler(CommandHandler("durdur", cmd_durdur))

    log.info("Telegram botu başlatıldı. Komutlar bekleniyor…")

    async with app:
        await app.start()
        await app.updater.start_polling(drop_pending_updates=True)

        import asyncio
        shutdown_event = system_state["bot_shutdown"]
        while not shutdown_event.is_set():
            await asyncio.sleep(1)

        await app.updater.stop()
        await app.stop()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    start_bot()
