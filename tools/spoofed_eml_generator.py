import argparse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "output"


def build_spoofed_bank() -> tuple[str, dict, str, str]:
    subject = " Güvenlik Uyarısı: Bu işlem size mi ait?"
    headers = {
        "From": '"Garanti BBVA Güvenlik" <guvenlik@garanti-bbva-online.xyz>',
        "Return-Path": "<bounce@totally-unrelated-spam-server.ru>",
        "Reply-To": "destek@garanti-bbva-online.xyz",
    }
    text = """\
Sayın Müşterimiz,

Hesabınızda yetkisiz giriş tespit edildi.

Bu işlem size mi ait?

[EVET — Benim işlemim]
[HAYIR — Benim değil] → https://garanti-bbva-online.xyz/verify?id=8834921

Hesabınız askıya alındı. Son uyarı olarak bildirilmektedir.
Hemen tıklayın ve kimliğinizi onaylayın, aksi takdirde
hesabınız kapatılacak.

24 saat içinde işlem yapılmazsa hesabınız silinecektir.

Güvenlik Departmanı
"""
    html = """\
<html><body>
<h2 style="color:red;"> Güvenlik Uyarısı</h2>
<p>Hesabınızda yetkisiz giriş tespit edildi.</p>
<h3>Bu işlem size mi ait?</h3>
<a href="https://garanti-bbva-online.xyz/verify?id=8834921">
  HAYIR — Benim değil, hemen tıklayın
</a>
<p>Hesabınız askıya alındı. Son uyarı.</p>
</body></html>
"""
    return subject, headers, text, html


def build_spoofed_it_support() -> tuple[str, dict, str, str]:
    subject = "[Acil] Şifre Süresi Doldu - Hemen İşlem Yapın"
    headers = {
        "From": '"IT Destek Ekibi" <it-support@company-portal-secure.info>',
        "Return-Path": "<noreply@mail-relay-99.cn>",
        "X-Mailer": "PHPMailer 5.2.9",
    }
    text = """\
Merhaba,

Şirket şifrenizin süresi bugün doluyor. Hesabınızın kilitlenmemesi için
hemen aşağıdaki bağlantıdan doğrulama yapmanız gerekmektedir.

Doğrulama linki: https://company-portal-secure.info/reset?token=xk29fa

Bu işlemi 2 saat içinde tamamlamazsanız hesabınız otomatik olarak
askıya alınacak ve BT ekibiyle manuel iletişime geçmeniz gerekecektir.

Şüpheli işlem tespit edildi, kimliğinizi doğrulayın.

IT Destek Ekibi
"""
    html = f"<html><body><p>{text}</p></body></html>"
    return subject, headers, text, html


def build_spoofed_shipping() -> tuple[str, dict, str, str]:
    subject = "Kargonuz Teslim Edilemedi - Adres Onayı Gerekli"
    headers = {
        "From": '"PTT Kargo Takip" <bildirim@ptt-kargo-takip.net>',
        "Return-Path": "<bulk@cheap-smtp-provider.top>",
    }
    text = """\
Sayın Alıcı,

Kargonuz adresinize teslim edilemedi. Lütfen aşağıdaki bağlantıdan
teslimat bilgilerinizi güncelleyerek işlemi hemen tamamlayın.

Onay linki: https://ptt-kargo-takip.net/confirm?tracking=TR884921037

Bu işlem yapılmazsa kargonuz 24 saat içinde iade edilecektir.
Acil işlem gerekiyor, hemen tıklayın.

PTT Kargo
"""
    html = f"<html><body><p>{text}</p></body></html>"
    return subject, headers, text, html


SCENARIOS = {
    "bank": ("Sahte Banka Phishing'i", build_spoofed_bank),
    "it_support": ("Sahte IT Destek Phishing'i", build_spoofed_it_support),
    "shipping": ("Sahte Kargo Phishing'i", build_spoofed_shipping),
}

PHISHTANK_FEED_URL = "https://data.phishtank.com/data/online-valid.json"


def fetch_phishtank_samples(count: int = 3, target_keyword: str = "") -> list[dict]:
    import requests
    import json as _json

    try:
        print("  ⏳ PhishTank herkese açık feed'i indiriliyor (biraz sürebilir)...")
        resp = requests.get(
            PHISHTANK_FEED_URL,
            headers={"User-Agent": "PhishGuard-TestGenerator/1.0"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as e:
        print(f"  PhishTank feed'ine erişilemedi: {e}")
        print("     Kendi ağınızda data.phishtank.com'a erişim açık olduğundan emin olun.")
        return []
    except _json.JSONDecodeError:
        print("  PhishTank yanıtı JSON olarak ayrıştırılamadı (rate limit olabilir).")
        return []

    verified = [
        entry for entry in data
        if entry.get("verified") == "yes" and entry.get("online") == "yes"
    ]

    if target_keyword:
        verified = [
            e for e in verified
            if target_keyword.lower() in (e.get("target") or "").lower()
        ]

    samples = verified[:count]
    print(f"   {len(samples)} doğrulanmış phishing URL'i bulundu.")

    return [
        {
            "url": e.get("url", ""),
            "target": e.get("target", "Bilinmiyor"),
            "phish_id": e.get("phish_id", ""),
            "verified_at": e.get("verification_time", ""),
        }
        for e in samples
    ]


def build_from_phishtank(sample: dict) -> tuple[str, dict, str, str]:
    target = sample.get("target", "Bilinmiyor")
    url = sample.get("url", "")
    phish_id = sample.get("phish_id", "")

    subject = f"[Doğrulama Gerekli] {target} Hesap Bildirimi"
    headers = {
        "From": f'"{target} Destek" <support@{_fake_domain_from(target)}>',
        "Return-Path": "<bounce@bulk-mailer-relay.top>",
        "X-PhishTank-ID": str(phish_id),
    }
    text = f"""\
Sayın Müşterimiz,

{target} hesabınızda olağandışı bir işlem tespit edildi.

Bu işlem size mi ait?

Hesabınızı doğrulamak ve güvenliğini sağlamak için lütfen
aşağıdaki bağlantıya tıklayın:

{url}

Bu işlemi 24 saat içinde tamamlamazsanız hesabınız askıya alınacaktır.
Şüpheli işlem, hemen tıklayın ve kimliğinizi onaylayın.

{target} Güvenlik Ekibi

---
Not: Bu, PhishTank'ta doğrulanmış gerçek bir phishing URL'i kullanır
(phish_id: {phish_id}). Yalnızca test/tespit amaçlıdır.
"""
    html = f"<html><body><p>{text.replace(chr(10), '<br>')}</p></body></html>"
    return subject, headers, text, html


def _fake_domain_from(target: str) -> str:
    import re as _re
    slug = _re.sub(r"[^a-zA-Z0-9]", "", target).lower() or "target"
    return f"{slug}-secure-verify.info"


_URL_COLUMN_CANDIDATES = ["url", "URL", "phish_url", "website_url"]
_URL_COLUMN_CANDIDATES = ["url", "URL", "phish_url", "website_url"]
_TARGET_COLUMN_CANDIDATES = ["target", "Target", "brand", "company"]
_ID_COLUMN_CANDIDATES = ["phish_id", "id", "ID", "phishtank_id"]
_ONLINE_COLUMN_CANDIDATES = ["online", "status"]
_LABEL_COLUMN_CANDIDATES = ["Label", "label", "class", "Class"]


def _find_column(fieldnames: list[str], candidates: list[str]) -> str | None:
    lower_map = {f.lower(): f for f in fieldnames}
    for name in candidates:
        if name.lower() in lower_map:
            return lower_map[name.lower()]
    return None


def load_phishtank_kaggle_csv(
    csv_path: str = "data/phishtank_valid.csv",
    count: int = 3,
    target_keyword: str = "",
) -> list[dict]:
    import csv
    import random

    path = Path(csv_path)
    if not path.exists():
        print(f"   Dosya bulunamadı: {path}")
        print(f"     Önce indirin: kaggle datasets download -d "
              f"quangnguynv/phishtank-phishingurl-valid-dataset -p data/ --unzip")
        return []

    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []

            url_col = _find_column(fieldnames, _URL_COLUMN_CANDIDATES)
            target_col = _find_column(fieldnames, _TARGET_COLUMN_CANDIDATES)
            id_col = _find_column(fieldnames, _ID_COLUMN_CANDIDATES)
            online_col = _find_column(fieldnames, _ONLINE_COLUMN_CANDIDATES)
            label_col = _find_column(fieldnames, _LABEL_COLUMN_CANDIDATES)

            if not url_col:
                print(f"   CSV'de URL sütunu bulunamadı. Mevcut sütunlar: {fieldnames}")
                print(f"     _URL_COLUMN_CANDIDATES listesine gerçek sütun adını ekleyin.")
                return []

            print(
                f"    Kullanılan sütunlar: url='{url_col}', "
                f"target='{target_col}', id='{id_col}', "
                f"online='{online_col}', label='{label_col}'"
            )

            rows = list(reader)
    except Exception as e:
        print(f"   CSV okunamadı: {e}")
        return []

    if label_col:
        before = len(rows)
        rows = [
            r for r in rows
            if str(r.get(label_col, "")).strip() in ("1", "1.0", "phishing", "bad")
        ]
        print(f"   Label filtresi: {before} kayıttan {len(rows)} tanesi phishing (Label=1).")

    elif online_col:
        online_values = {"yes", "1", "true", "online", "valid"}
        filtered = [
            r for r in rows
            if str(r.get(online_col, "")).strip().lower() in online_values
        ]
        rows = filtered if filtered else rows

    if target_keyword and target_col:
        rows = [
            r for r in rows
            if target_keyword.lower() in str(r.get(target_col, "")).lower()
        ]
    elif target_keyword and not target_col:
        print("   --target verildi ama CSV'de marka/target sütunu yok, filtre atlandı.")

    if not rows:
        print("    Filtrelere uyan kayıt bulunamadı.")
        return []

    random.shuffle(rows)
    samples = rows[:count]

    print(f"  {len(samples)} kayıt Kaggle CSV'den okundu (toplam {len(rows)} uygun kayıt).")

    return [
        {
            "url": row.get(url_col, ""),
            "target": row.get(target_col, "Bilinmiyor") if target_col else "Bilinmiyor",
            "phish_id": row.get(id_col, "") if id_col else "",
            "verified_at": "",
        }
        for row in samples
    ]


def build_eml(subject: str, headers: dict, text: str, html: str) -> bytes:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["To"] = "test@localhost"

    for key, value in headers.items():
        msg[key] = value

    msg.attach(MIMEText(text, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))
    return msg.as_bytes()


def generate(scenario_key: str) -> Path:
    label, builder = SCENARIOS[scenario_key]
    subject, headers, text, html = builder()
    raw = build_eml(subject, headers, text, html)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTPUT_DIR / f"spoofed_{scenario_key}.eml"
    with open(out_path, "wb") as f:
        f.write(raw)

    print(f"   {label} → {out_path}")
    print(f"     Test etmek için: python src/detector.py {out_path}")
    return out_path


def generate_from_phishtank(
    count: int,
    target_keyword: str = "",
    source: str = "live",
    csv_path: str = "data/phishtank_valid.csv",
) -> list[Path]:
    if source == "kaggle":
        samples = load_phishtank_kaggle_csv(
            csv_path=csv_path, count=count, target_keyword=target_keyword
        )
    else:
        samples = fetch_phishtank_samples(count=count, target_keyword=target_keyword)

    if not samples:
        print("   Hiç örnek alınamadı, .eml üretilmedi.")
        return []

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    paths = []

    for i, sample in enumerate(samples, 1):
        subject, headers, text, html = build_from_phishtank(sample)
        raw = build_eml(subject, headers, text, html)

        out_path = OUTPUT_DIR / f"phishtank_real_{i}.eml"
        with open(out_path, "wb") as f:
            f.write(raw)

        print(f"  Gerçek phishing örneği #{i} (hedef: {sample['target']}) → {out_path}")
        if sample.get("phish_id"):
            print(f"     PhishTank kaydı: phish_id={sample['phish_id']}")
        print(f"     Test etmek için: python src/detector.py {out_path}")
        paths.append(out_path)

    return paths


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Spoofed phishing .eml üretici — gerçek saldırgan header'larını taklit eder"
    )
    parser.add_argument(
        "--scenario",
        default="all",
        choices=list(SCENARIOS.keys()) + ["all", "phishtank"],
        help="Üretilecek senaryo. 'phishtank' = PhishTank'tan gerçek URL çek.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=3,
        help="--scenario phishtank ile kullanılır: kaç gerçek örnek çekilsin (varsayılan 3)",
    )
    parser.add_argument(
        "--target",
        default="",
        help="--scenario phishtank ile kullanılır: belirli bir marka ile filtrele (örn. PayPal)",
    )
    parser.add_argument(
        "--source",
        default="kaggle",
        choices=["live", "kaggle"],
        help=(
            "--scenario phishtank ile kullanılır: 'live' canlı PhishTank API'sini "
            "dener (internet + rate limit riski), 'kaggle' önceden indirdiğiniz "
            "CSV'yi okur (varsayılan, daha güvenilir)."
        ),
    )
    parser.add_argument(
        "--csv-path",
        default="data/phishtank_valid.csv",
        help="--source kaggle ile kullanılır: indirdiğiniz CSV dosyasının yolu",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  Spoofed Phishing .eml Üretici")
    print("=" * 60)
    print()

    if args.scenario == "phishtank":
        print(f"  Gerçek phishing URL'leri alınıyor (kaynak: {args.source})...")
        if args.source == "live":
            print("     (Anahtar gerekmez, herkese açık feed kullanılıyor — 403/404 riski var)")
        else:
            print(f"     (Kaggle CSV: {args.csv_path})")
        print()
        generate_from_phishtank(
            count=args.count,
            target_keyword=args.target,
            source=args.source,
            csv_path=args.csv_path,
        )
        return

    targets = list(SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]
    for key in targets:
        generate(key)

    print()
    print("─" * 60)
    print("  Üretilen dosyaları test edin (mail göndermeden):")
    print("─" * 60)
    for key in targets:
        print(f"  python src/detector.py output/spoofed_{key}.eml")
    print()
    print("  Gerçek, güncel phishing URL'leri denemek isterseniz:")
    print("     python tools/spoofed_eml_generator.py --scenario phishtank --count 3")


if __name__ == "__main__":
    main()
