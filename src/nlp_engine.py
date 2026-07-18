import logging
import pickle
from pathlib import Path

log = logging.getLogger("PhishScan.NLPEngine")

PROJECT_ROOT = Path(__file__).parent.parent

BOOST_HIGH_CONFIDENCE_PHISHING = 20
BOOST_MODERATE_PHISHING = 10
BOOST_LIKELY_CLEAN = -10

THRESHOLD_HIGH_CONFIDENCE = 0.80
THRESHOLD_MODERATE = 0.60
THRESHOLD_LIKELY_CLEAN = 0.30

DEFAULT_GREY_ZONE_MIN = 35
DEFAULT_GREY_ZONE_MAX = 59

DEFAULT_HF_MODEL_ID = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
DEFAULT_REMOTE_MAX_CHARS = 200


def _load_config() -> dict:
    import json
    config_path = PROJECT_ROOT / "config.json"
    if config_path.exists():
        return json.loads(config_path.read_text(encoding="utf-8"))
    return {}


PHISHING_TRAINING_SAMPLES = [
    "Bu işlem size mi ait? Hemen tıklayın ve kimliğinizi doğrulayın.",
    "Hesabınız askıya alındı. 24 saat içinde doğrulayın.",
    "Yetkisiz giriş tespit edildi. Şifrenizi hemen sıfırlayın.",
    "Son uyarı: Hesabınız kapatılacak. Acil işlem gerekiyor.",
    "Ödeme bilgilerinizi güncelleyin yoksa hesabınız dondurulacak.",
    "Güvenlik ihlali tespit edildi. Kimliğinizi onaylayın.",
    "Tebrikler! 50.000 TL kazandınız. Hemen tıklayın.",
    "Verify your account immediately to avoid suspension.",
    "Unusual activity detected. Confirm your identity now.",
    "Your account will be suspended. Click here to update payment.",
    "Security alert: unauthorized access to your account.",
    "Click immediately to claim your reward before it expires.",
    "Your password has been compromised. Reset it now.",
    "Dear customer, your bank account requires verification.",
    "Hesabınıza farklı bir cihazdan giriş yapıldı. Siz değilseniz tıklayın.",
    "Kredi kartınız bloke edildi. Kimliğinizi doğrulayın.",
    "İşleminiz onay bekliyor. 1 saat içinde işlem yapmazsanız iptal edilecek.",
    "Şüpheli işlem tespit edildi. Hemen hesabınızı kontrol edin.",
    "You have a pending transaction. Verify now or it will be cancelled.",
    "Congratulations! You have been selected for a special offer.",
    "Your invoice is attached. Please review and confirm payment details.",
    "Action required: complete your profile to avoid account closure.",
    "We noticed a sign-in from a new device. If this wasn't you, click here.",
    "Your subscription will expire. Update your billing information now.",
    "URGENT: Your email account has been hacked. Change password immediately.",
]

CLEAN_TRAINING_SAMPLES = [
    "Haftalık proje raporu ektedir. İyi çalışmalar.",
    "Toplantı saatini Çarşamba 14:00 olarak güncelledim.",
    "Teklif dosyasını inceledim, birkaç düzeltme öneririm.",
    "Bu ay teslim edilen görevlerin listesi aşağıdadır.",
    "Randevunuz onaylanmıştır. Bilgi için lütfen bizi arayın.",
    "Please find the meeting notes attached to this email.",
    "The quarterly report is ready for your review.",
    "Thank you for your order. Your shipment is on its way.",
    "Your appointment has been confirmed for next Monday.",
    "We are happy to inform you that your application was accepted.",
    "Here is the summary of today's team meeting.",
    "Your package has been delivered to the front door.",
    "Newsletter: Here are this month's top articles for you.",
    "Reminder: Please complete your timesheet by Friday.",
    "Your tax document is ready to download from the portal.",
    "Project milestone reached! Great work team.",
    "The attached file contains the updated schedule.",
    "Aşağıdaki belgeleri imzalayıp iade edebilir misiniz?",
    "Ekip toplantısı Perşembe günü saat 10:00'da yapılacaktır.",
    "Siparişiniz kargoya verilmiştir. Takip numaranız aşağıdadır.",
    "Ürünümüzü tercih ettiğiniz için teşekkür ederiz.",
    "Faturanız sisteme yüklenmiştir. Portal üzerinden inceleyebilirsiniz.",
    "Bu ay düzenlediğimiz etkinliğe katılmanızı bekliyoruz.",
    "Destek talebiniz alınmıştır. En kısa sürede dönüş yapacağız.",
    "Yeni ürün kataloğumuzu incelemenizi öneririz.",
]

BUILTIN_CORPUS: list[tuple[str, int]] = (
    [(text, 1) for text in PHISHING_TRAINING_SAMPLES]
    + [(text, 0) for text in CLEAN_TRAINING_SAMPLES]
)


class LocalNLPModel:
    def __init__(self, model_path: str = "data/phishscan_nlp.pkl"):
        self.model_path = PROJECT_ROOT / model_path
        self._pipeline = None
        self._load_or_train()

    def _load_or_train(self) -> None:
        if self.model_path.exists():
            try:
                with open(self.model_path, "rb") as f:
                    self._pipeline = pickle.load(f)
                log.info(f"NLP modeli yüklendi: {self.model_path}")
                return
            except Exception as exc:
                log.warning(f"Model yüklenemedi ({exc}), yeniden eğitiliyor…")
        self._train(BUILTIN_CORPUS)

    def _train(self, corpus: list[tuple[str, int]]) -> None:
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.linear_model import LogisticRegression
            from sklearn.pipeline import Pipeline
        except ImportError:
            log.error("scikit-learn kurulu değil. Kurmak için: pip install scikit-learn")
            return

        texts, labels = zip(*corpus)

        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                analyzer="word", ngram_range=(1, 2), max_features=5000,
                sublinear_tf=True, lowercase=True,
            )),
            ("clf", LogisticRegression(
                C=1.0, max_iter=1000, random_state=42, class_weight="balanced",
            )),
        ])
        pipeline.fit(texts, labels)

        self._pipeline = pipeline
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.model_path, "wb") as f:
            pickle.dump(pipeline, f)
        log.info(f"NLP modeli eğitildi ({len(corpus)} örnek) → {self.model_path}")

    def retrain(self, extra_samples: list[tuple[str, int]]) -> None:
        self._train(BUILTIN_CORPUS + extra_samples)

    def predict(self, text: str) -> float | None:
        if self._pipeline is None:
            log.warning("NLP modeli hazır değil, tahmin atlandı.")
            return None
        try:
            phishing_probability = self._pipeline.predict_proba([text])[0][1]
            return float(phishing_probability)
        except Exception as exc:
            log.error(f"NLP tahmin hatası: {exc}")
            return None


class RemoteAPIProvider:
    def __init__(self, config: dict):
        self.api_key = config.get("huggingface_api_key", "")
        self.model_id = config.get("huggingface_model_id", DEFAULT_HF_MODEL_ID)
        self.max_chars = config.get("nlp_remote_max_chars", DEFAULT_REMOTE_MAX_CHARS)
        self.sanitize_before_send = config.get("nlp_sanitize_before_send", True)

    def _prepare_text(self, text: str) -> str:
        if not self.sanitize_before_send:
            log.warning("Sanitizasyon devre dışı — metin ham halde gönderiliyor!")
            return text[:self.max_chars]

        from sanitizer import sanitize_for_api
        safe_text, meta = sanitize_for_api(text, max_chars=self.max_chars)
        log.info(f"Sanitizasyon uygulandı: {meta}")
        return safe_text

    def predict(self, text: str) -> float | None:
        import requests

        safe_text = self._prepare_text(text)
        url = f"https://api-inference.huggingface.co/models/{self.model_id}"
        headers = {"Authorization": f"Bearer {self.api_key}"}

        try:
            response = requests.post(
                url, headers=headers, json={"inputs": safe_text}, timeout=15
            )
            response.raise_for_status()
            data = response.json()

            if isinstance(data, list) and data:
                results = data[0] if isinstance(data[0], list) else data
                for item in results:
                    if item.get("label", "").upper() in ("SPAM", "PHISHING", "LABEL_1", "1"):
                        return float(item.get("score", 0.0))
                return 0.0

        except requests.exceptions.Timeout:
            log.warning("HuggingFace API zaman aşımı.")
        except Exception as exc:
            log.error(f"HuggingFace API hatası: {exc}")

        return None


_provider = None
_provider_name = "disabled"


def _init_provider() -> None:
    global _provider, _provider_name

    config = _load_config()
    _provider_name = config.get("nlp_provider", "disabled").lower().strip()

    if _provider_name == "disabled":
        log.info("NLP provider devre dışı (Secure by Default).")
        return

    if _provider_name == "local":
        try:
            model_path = config.get("nlp_model_path", "data/phishscan_nlp.pkl")
            _provider = LocalNLPModel(model_path=model_path)
            log.info("Yerel NLP modeli hazır.")
        except Exception as exc:
            log.error(f"Yerel NLP modeli başlatılamadı: {exc}")
            _provider_name = "disabled"
        return

    if _provider_name == "remote_api":
        log.warning(
            " NLP provider 'remote_api' aktif. "
            "E-posta içeriği (maskelenmiş) dış sunucuya gönderilecek."
        )
        _provider = RemoteAPIProvider(config)
        return

    log.warning(f"Bilinmeyen nlp_provider değeri: '{_provider_name}' — devre dışı bırakıldı.")
    _provider_name = "disabled"


def _skipped_result(reason: str) -> dict:
    log.debug(f"NLP atlandı: {reason}")
    return {
        "nlp_provider": _provider_name, "nlp_score": None,
        "nlp_boost": 0, "nlp_label": "N/A", "applied": False,
    }


def _score_to_boost(probability: float) -> tuple[int, str]:
    if probability > THRESHOLD_HIGH_CONFIDENCE:
        return BOOST_HIGH_CONFIDENCE_PHISHING, "PHISHING"
    if probability > THRESHOLD_MODERATE:
        return BOOST_MODERATE_PHISHING, "PHISHING"
    if probability < THRESHOLD_LIKELY_CLEAN:
        return BOOST_LIKELY_CLEAN, "CLEAN"
    return 0, "UNCERTAIN"


def refine(body_text: str, current_score: int, config: dict | None = None) -> dict:
    active_config = config or _load_config()
    grey_min = active_config.get("nlp_grey_zone_min", DEFAULT_GREY_ZONE_MIN)
    grey_max = active_config.get("nlp_grey_zone_max", DEFAULT_GREY_ZONE_MAX)

    if _provider is None or _provider_name == "disabled":
        return _skipped_result("NLP devre dışı.")

    if not (grey_min <= current_score <= grey_max):
        return _skipped_result(
            f"Skor ({current_score}) gri alan dışında [{grey_min}-{grey_max}]."
        )

    try:
        probability = _provider.predict(body_text)
    except Exception as exc:
        log.warning(f"NLP predict() hatası: {exc}")
        return _skipped_result("predict() exception fırlattı.")

    if probability is None:
        return _skipped_result("NLP tahmini başarısız.")

    boost, label = _score_to_boost(probability)
    log.info(f"NLP ({_provider_name}): olasılık={probability:.3f} label={label} boost={boost:+d}")

    return {
        "nlp_provider": _provider_name,
        "nlp_score": round(probability, 4),
        "nlp_boost": boost,
        "nlp_label": label,
        "applied": True,
    }


def get_model() -> LocalNLPModel | None:
    if _provider_name == "local" and isinstance(_provider, LocalNLPModel):
        return _provider
    return None


_init_provider()
