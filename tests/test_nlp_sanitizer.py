import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestSanitizer:

    def _s(self):
        from sanitizer import sanitize
        return sanitize

    def test_http_url_masked(self):
        sanitize = self._s()
        text, stats = sanitize("Şuraya gidin: https://evil.example.com/login?token=abc")
        assert "[REDACTED_URL]" in text
        assert "evil.example.com" not in text
        assert stats.get("URL", 0) >= 1

    def test_ftp_url_masked(self):
        sanitize = self._s()
        text, _ = sanitize("Dosyayı ftp://files.internal.net/doc.zip adresinden indirin.")
        assert "[REDACTED_URL]" in text

    def test_multiple_urls_all_masked(self):
        sanitize = self._s()
        raw = "https://link1.com ve https://link2.com ve https://link3.com"
        text, stats = sanitize(raw)
        assert stats["URL"] == 3
        assert text.count("[REDACTED_URL]") == 3

    def test_email_masked(self):
        sanitize = self._s()
        text, stats = sanitize("Bize ulaşın: destek@phishbank.com")
        assert "[REDACTED_EMAIL]" in text
        assert "phishbank.com" not in text
        assert stats.get("EMAIL", 0) == 1

    def test_email_in_angle_brackets_masked(self):
        sanitize = self._s()
        text, _ = sanitize("From: Ali Veli <ali.veli@suspicious.xyz>")
        assert "[REDACTED_EMAIL]" in text

    def test_ipv4_masked(self):
        sanitize = self._s()
        text, stats = sanitize("Giriş IP: 192.168.1.105")
        assert "[REDACTED_IP]" in text
        assert "192.168.1.105" not in text

    def test_full_range_ipv4_masked(self):
        sanitize = self._s()
        text, _ = sanitize("Sunucu adresi: 10.0.0.1 ve 255.255.255.0")
        assert "10.0.0.1" not in text
        assert "255.255.255.0" not in text

    def test_tckn_masked(self):
        sanitize = self._s()
        text, stats = sanitize("TC Kimlik No: 12345678901")
        assert "[REDACTED_TCKN]" in text
        assert "12345678901" not in text
        assert stats.get("TCKN", 0) == 1

    def test_tckn_starting_with_zero_not_masked(self):
        sanitize = self._s()
        text, stats = sanitize("Sayı: 01234567890")
        assert stats.get("TCKN", 0) == 0

    def test_iban_masked(self):
        sanitize = self._s()
        text, stats = sanitize("IBAN: TR33 0006 1005 1978 6457 8413 26")
        assert "[REDACTED_IBAN]" in text
        assert stats.get("IBAN", 0) == 1

    def test_credit_card_masked(self):
        sanitize = self._s()
        text, stats = sanitize("Kart: 4532 1488 0343 6467")
        assert "[REDACTED_CARD]" in text
        assert stats.get("CARD", 0) == 1

    def test_credit_card_with_dash_masked(self):
        sanitize = self._s()
        text, _ = sanitize("Kart: 4532-1488-0343-6467")
        assert "[REDACTED_CARD]" in text

    def test_turkish_mobile_masked(self):
        sanitize = self._s()
        text, stats = sanitize("Telefon: +90 532 123 45 67")
        assert "[REDACTED_PHONE]" in text

    def test_mobile_without_country_code_masked(self):
        sanitize = self._s()
        text, _ = sanitize("Bizi arayın: 0532 123 45 67")
        assert "[REDACTED_PHONE]" in text

    def test_rule_filter_only_selected_rules_applied(self):
        sanitize = self._s()
        text = "Email: test@evil.com IP: 1.2.3.4"
        masked, stats = sanitize(text, rules=["EMAIL"])
        assert "[REDACTED_EMAIL]" in masked
        assert "1.2.3.4" in masked
        assert "IPV4" not in stats

    def test_sanitize_for_api_truncates(self):
        from sanitizer import sanitize_for_api
        long_text = "Hesabınız askıya alındı. " * 50
        result, meta = sanitize_for_api(long_text, max_chars=100)
        assert len(result) <= 115
        assert meta["truncated"] is True

    def test_sanitize_for_api_no_truncation_when_short(self):
        from sanitizer import sanitize_for_api
        short_text = "Kısa bir metin."
        result, meta = sanitize_for_api(short_text, max_chars=200)
        assert meta["truncated"] is False
        assert "kırpıldı" not in result

    def test_sanitize_for_api_masks_and_truncates_together(self):
        from sanitizer import sanitize_for_api
        text = "Email: phish@evil.com " * 20
        result, meta = sanitize_for_api(text, max_chars=80)
        assert "[REDACTED_EMAIL]" in result
        assert meta["truncated"] is True

    def test_clean_text_unchanged(self):
        sanitize = self._s()
        clean = "Haftalık rapor ektedir. İyi çalışmalar."
        result, stats = sanitize(clean)
        assert result == clean
        assert stats == {}

    def test_empty_string_handled(self):
        sanitize = self._s()
        result, stats = sanitize("")
        assert result == ""
        assert stats == {}


class TestNLPEngine:

    @pytest.fixture(autouse=True)
    def reset_provider(self, monkeypatch):
        import nlp_engine
        monkeypatch.setattr(nlp_engine, "_provider", None)
        monkeypatch.setattr(nlp_engine, "_provider_name", "disabled")

    def test_disabled_provider_returns_no_boost(self):
        from nlp_engine import refine
        result = refine(body_text="test", current_score=45)
        assert result["applied"] is False
        assert result["nlp_boost"] == 0
        assert result["nlp_label"] == "N/A"

    def test_disabled_provider_does_not_affect_score(self):
        from nlp_engine import refine
        result = refine(body_text="phishing tıklayın acil", current_score=50)
        assert result["nlp_boost"] == 0

    def test_nlp_skipped_below_grey_zone(self, monkeypatch):
        import nlp_engine
        mock_provider = MagicMock()
        mock_provider.predict.return_value = 0.9
        monkeypatch.setattr(nlp_engine, "_provider", mock_provider)
        monkeypatch.setattr(nlp_engine, "_provider_name", "local")

        result = refine_with_config("temiz metin", current_score=20)
        assert result["applied"] is False
        mock_provider.predict.assert_not_called()

    def test_nlp_skipped_above_grey_zone(self, monkeypatch):
        import nlp_engine
        mock_provider = MagicMock()
        mock_provider.predict.return_value = 0.9
        monkeypatch.setattr(nlp_engine, "_provider", mock_provider)
        monkeypatch.setattr(nlp_engine, "_provider_name", "local")

        result = refine_with_config("phishing", current_score=75)
        assert result["applied"] is False
        mock_provider.predict.assert_not_called()

    def test_nlp_runs_in_grey_zone(self, monkeypatch):
        import nlp_engine
        mock_provider = MagicMock()
        mock_provider.predict.return_value = 0.85
        monkeypatch.setattr(nlp_engine, "_provider", mock_provider)
        monkeypatch.setattr(nlp_engine, "_provider_name", "local")

        result = refine_with_config("phishing test", current_score=45)
        assert result["applied"] is True
        mock_provider.predict.assert_called_once()

    def test_high_nlp_score_gives_plus_20_boost(self, monkeypatch):
        import nlp_engine
        mock_p = MagicMock()
        mock_p.predict.return_value = 0.95
        monkeypatch.setattr(nlp_engine, "_provider", mock_p)
        monkeypatch.setattr(nlp_engine, "_provider_name", "local")

        result = refine_with_config("phishing", current_score=50)
        assert result["nlp_boost"] == 20
        assert result["nlp_label"] == "PHISHING"

    def test_medium_nlp_score_gives_plus_10_boost(self, monkeypatch):
        import nlp_engine
        mock_p = MagicMock()
        mock_p.predict.return_value = 0.70
        monkeypatch.setattr(nlp_engine, "_provider", mock_p)
        monkeypatch.setattr(nlp_engine, "_provider_name", "local")

        result = refine_with_config("şüpheli metin", current_score=40)
        assert result["nlp_boost"] == 10
        assert result["nlp_label"] == "PHISHING"

    def test_low_nlp_score_gives_minus_10_boost(self, monkeypatch):
        import nlp_engine
        mock_p = MagicMock()
        mock_p.predict.return_value = 0.10
        monkeypatch.setattr(nlp_engine, "_provider", mock_p)
        monkeypatch.setattr(nlp_engine, "_provider_name", "local")

        result = refine_with_config("temiz iş maili", current_score=38)
        assert result["nlp_boost"] == -10
        assert result["nlp_label"] == "CLEAN"

    def test_uncertain_nlp_score_gives_zero_boost(self, monkeypatch):
        import nlp_engine
        mock_p = MagicMock()
        mock_p.predict.return_value = 0.45
        monkeypatch.setattr(nlp_engine, "_provider", mock_p)
        monkeypatch.setattr(nlp_engine, "_provider_name", "local")

        result = refine_with_config("belirsiz metin", current_score=45)
        assert result["nlp_boost"] == 0
        assert result["nlp_label"] == "UNCERTAIN"

    def test_predict_returns_none_gracefully(self, monkeypatch):
        import nlp_engine
        mock_p = MagicMock()
        mock_p.predict.return_value = None
        monkeypatch.setattr(nlp_engine, "_provider", mock_p)
        monkeypatch.setattr(nlp_engine, "_provider_name", "local")

        result = refine_with_config("test", current_score=45)
        assert result["applied"] is False
        assert result["nlp_boost"] == 0

    def test_predict_raises_exception_gracefully(self, monkeypatch):
        import nlp_engine
        mock_p = MagicMock()
        mock_p.predict.side_effect = RuntimeError("model error")
        monkeypatch.setattr(nlp_engine, "_provider", mock_p)
        monkeypatch.setattr(nlp_engine, "_provider_name", "local")

        result = refine_with_config("test", current_score=45)
        assert result["nlp_boost"] == 0

    def test_local_model_trains_on_builtin_corpus(self, tmp_path):
        pytest.importorskip("sklearn", reason="scikit-learn kurulu değil")
        from nlp_engine import LocalNLPModel

        model_path = tmp_path / "test_model.pkl"
        model = LocalNLPModel(model_path=str(model_path))

        assert model_path.exists()

        score = model.predict("hesabınız askıya alındı hemen tıklayın")
        assert score is not None
        assert 0.0 <= score <= 1.0

    def test_local_model_phishing_higher_than_clean(self, tmp_path):
        pytest.importorskip("sklearn", reason="scikit-learn kurulu değil")
        from nlp_engine import LocalNLPModel

        model = LocalNLPModel(model_path=str(tmp_path / "m.pkl"))
        phishing_score = model.predict(
            "hesabınız askıya alındı. yetkisiz giriş. hemen tıklayın."
        )
        clean_score = model.predict(
            "haftalık proje raporu ektedir. iyi çalışmalar."
        )
        assert phishing_score > clean_score

    def test_local_model_loads_from_disk(self, tmp_path):
        pytest.importorskip("sklearn", reason="scikit-learn kurulu değil")
        from nlp_engine import LocalNLPModel

        path = str(tmp_path / "m.pkl")
        m1 = LocalNLPModel(model_path=path)
        s1 = m1.predict("test metni")

        m2 = LocalNLPModel(model_path=path)
        s2 = m2.predict("test metni")

        assert abs(s1 - s2) < 0.001

    def test_retrain_with_extra_samples(self, tmp_path):
        pytest.importorskip("sklearn", reason="scikit-learn kurulu değil")
        from nlp_engine import LocalNLPModel

        model = LocalNLPModel(model_path=str(tmp_path / "m.pkl"))
        extra = [
            ("bu kesinlikle phishing bir mesajdır acil tıklayın", 1),
            ("bu tamamen temiz bir iş yazışmasıdır", 0),
        ]
        model.retrain(extra)
        score = model.predict("acil tıklayın kimliğinizi doğrulayın")
        assert score is not None


class TestDetectorNLPBridge:

    @pytest.fixture(autouse=True)
    def mock_externals(self, mocker):
        mocker.patch(
            "dns.resolver.resolve",
            side_effect=Exception("DNS: test modu"),
        )
        mock_resp = MagicMock()
        mock_resp.url = "https://example.com"
        mocker.patch("requests.head", return_value=mock_resp)
        mock_vt = MagicMock()
        mock_vt.status_code = 200
        mock_vt.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 0, "suspicious": 0
            }}}
        }
        mocker.patch("requests.get", return_value=mock_vt)
        mocker.patch("requests.post", return_value=MagicMock(
            status_code=200,
            json=MagicMock(return_value={"uuid": "fake"})
        ))

    def _make_grey_zone_email(self) -> bytes:
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Güvenlik Bildirimi"
        msg["From"] = "noreply@unknowndomain-xyz.com"
        msg["To"] = "user@gmail.com"
        msg.attach(MIMEText("Acil durum bildirimi. Lütfen kontrol edin.", "plain", "utf-8"))
        return msg.as_bytes()

    def test_nlp_result_in_report(self, mocker):
        mocker.patch("detector.get_nlp_second_opinion", return_value={
            "nlp_provider": "local", "nlp_boost": 0,
            "nlp_label": "UNCERTAIN", "applied": True, "nlp_score": 0.45,
        })
        from detector import analyze_email
        result = analyze_email(self._make_grey_zone_email())
        assert "nlp" in result

    def test_positive_nlp_boost_increases_score(self, mocker):
        base_result = None

        def capture_base(*args, **kwargs):
            nonlocal base_result
            from detector import analyze_headers, analyze_content, analyze_urls, calculate_risk
            return {"nlp_provider": "local", "nlp_boost": 20,
                    "nlp_label": "PHISHING", "applied": True, "nlp_score": 0.92}

        mocker.patch("detector.get_nlp_second_opinion", side_effect=capture_base)
        from detector import analyze_email
        raw = self._make_grey_zone_email()
        result = analyze_email(raw)

        assert result["nlp"]["nlp_boost"] == 20

    def test_negative_nlp_boost_decreases_score(self, mocker):
        mocker.patch("detector.get_nlp_second_opinion", return_value={
            "nlp_provider": "local", "nlp_boost": -10,
            "nlp_label": "CLEAN", "applied": True, "nlp_score": 0.08,
        })
        from detector import analyze_email
        result = analyze_email(self._make_grey_zone_email())
        assert result["nlp"]["nlp_boost"] == -10

    def test_score_never_exceeds_100_with_boost(self, mocker):
        mocker.patch("detector.get_nlp_second_opinion", return_value={
            "nlp_provider": "local", "nlp_boost": 20,
            "nlp_label": "PHISHING", "applied": True, "nlp_score": 0.99,
        })
        from detector import analyze_email
        result = analyze_email(self._make_grey_zone_email())
        assert result["risk_score"] <= 100

    def test_score_never_below_zero_with_boost(self, mocker):
        mocker.patch("detector.get_nlp_second_opinion", return_value={
            "nlp_provider": "local", "nlp_boost": -999,
            "nlp_label": "CLEAN", "applied": True, "nlp_score": 0.01,
        })
        from detector import analyze_email
        result = analyze_email(self._make_grey_zone_email())
        assert result["risk_score"] >= 0

    def test_nlp_not_applied_skips_gracefully(self, mocker):
        mocker.patch("detector.get_nlp_second_opinion", return_value={
            "nlp_provider": "disabled", "nlp_boost": 0,
            "nlp_label": "N/A", "applied": False,
        })
        from detector import analyze_email
        result = analyze_email(self._make_grey_zone_email())
        assert "verdict" in result
        assert "risk_score" in result


def refine_with_config(body_text: str, current_score: int) -> dict:
    from nlp_engine import refine
    return refine(
        body_text=body_text,
        current_score=current_score,
        config={"nlp_grey_zone_min": 35, "nlp_grey_zone_max": 59},
    )
