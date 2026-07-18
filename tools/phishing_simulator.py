

import argparse
import smtplib
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587


def build_clean_email() -> tuple[str, str, str]:
    
    subject = "Q3 Raporu — Haftalık Durum Güncellemesi"
    text = (
        "Merhaba,\n"
        "Bu hafta tamamlanan görevleri özetledim.\n"
        "İyi çalışmalar,\nAhmet Yılmaz"
    )
    html = (
        "<html><body><p>Merhaba,</p>"
        "<p>Bu hafta tamamlanan görevleri özetledim.</p>"
        "<p>İyi çalışmalar,<br>Ahmet Yılmaz</p></body></html>"
    )
    return subject, text, html


def build_suspicious_email() -> tuple[str, str, str]:
    
    subject = "[Acil] Hesap Güvenlik Bildirimi"
    text = "Hesabınızda güvenlik ihlali tespit edilmiştir. Acil destekle iletişime geçin."
    html = (
        "<html><body><h2 style='color:red;'>[Acil] Hesap Güvenlik Bildirimi</h2>"
        "<p>Güvenlik ihlali tespit edildi. Acil destekle iletişime geçin.</p>"
        "</body></html>"
    )
    return subject, text, html


def build_critical_phishing_email() -> tuple[str, str, str]:
    """Senaryo 3 — Kritik Oltalama Payload'u (Beklenen: QUARANTINE)."""
    subject = " Güvenlik Uyarısı: Bu işlem size mi ait?"
    text = (
        "Yetkisiz giriş! Doğrulamak için: https://example.com/account-verify\n"
        "Hemen tıklayın aksi takdirde hesap askıya alınacak."
    )
    html = (
        "<html><body><h2 style='color:red;'> Güvenlik Uyarısı</h2>"
        "<p>Yetkisiz giriş! Doğrulamak için: "
        "<a href='https://example.com/account-verify'>Hemen tıklayın</a> "
        "aksi takdirde hesap askıya alınacak.</p></body></html>"
    )
    return subject, text, html


SCENARIOS = {
    1: ("Temiz E-posta", "PASS", build_clean_email),
    2: ("Şüpheli Uyarı", "WARN", build_suspicious_email),
    3: ("Kritik Phishing", "QUARANTINE", build_critical_phishing_email),
}


def send_test_email(
    sender: str, password: str, target: str,
    subject: str, text: str, html: str, scenario_no: int,
) -> bool:
    
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = f"PhishScan Test <{sender}>"
    message["To"] = target
    message["X-PhishScan-Scenario"] = str(scenario_no)

    message.attach(MIMEText(text, "plain", "utf-8"))
    message.attach(MIMEText(html, "html", "utf-8"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(sender, password)
            smtp.sendmail(sender, target, message.as_bytes())
        return True
    except smtplib.SMTPAuthenticationError:
        print(
            " Kimlik doğrulama hatası. Google Hesabı → Güvenlik → "
            "Uygulama Şifreleri üzerinden bir şifre oluşturun."
        )
        return False
    except Exception as exc:
        print(f" Gönderim hatası: {exc}")
        return False


def run_simulation(sender: str, password: str, target: str, scenario: str) -> None:
    scenario_numbers = list(SCENARIOS.keys()) if scenario == "all" else [int(scenario)]

    print(f"\nPhishScan Simülatörü Başladı [{datetime.now().strftime('%H:%M:%S')}]")
    print("-" * 50)

    for number in scenario_numbers:
        label, expected_verdict, build_email = SCENARIOS[number]
        subject, text, html = build_email()

        print(f"▶ Senaryo {number}: {label} (Beklenen: {expected_verdict})")
        success = send_test_email(sender, password, target, subject, text, html, number)
        print(" Gönderildi" if success else "❌ Başarısız")

        if number != scenario_numbers[-1]:
            time.sleep(3)

    print("-" * 50)
    print("E-postalar gönderildi. Tarama motorunu kontrol edebilirsiniz.")


def main() -> None:
    parser = argparse.ArgumentParser(description="PhishScan — Canlı Simülasyon Betiği")
    parser.add_argument("--sender", required=True, help="Gönderen Gmail adresi")
    parser.add_argument("--password", required=True, help="Google Uygulama Şifresi")
    parser.add_argument("--target", required=True, help="Hedef e-posta adresi")
    parser.add_argument("--scenario", default="all", choices=["1", "2", "3", "all"])

    args = parser.parse_args()
    run_simulation(args.sender, args.password, args.target, args.scenario)


if __name__ == "__main__":
    main()
