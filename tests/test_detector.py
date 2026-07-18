import sys
import types
import textwrap
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from unittest.mock import MagicMock, patch

import pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def make_email(
    subject: str = "Test",
    from_addr: str = "sender@example.com",
    body_text: str = "",
    body_html: str = "",
    dkim_signature: str = "",
) -> bytes:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = "recipient@example.com"

    if dkim_signature:
        msg["DKIM-Signature"] = dkim_signature

    if body_text:
        msg.attach(MIMEText(body_text, "plain", "utf-8"))
    if body_html:
        msg.attach(MIMEText(body_html, "html", "utf-8"))
    elif body_text and not body_html:
        pass

    return msg.as_bytes()


def make_phishing_email() -> bytes:
    html = textwrap.dedent("""\
        <html><body>
        <p>Hesabınızda <strong>yetkisiz giriş</strong> tespit edildi.</p>
        <h3>Bu işlem size mi ait?</h3>
        <a href="https://bit.ly/3xFakePhish">Hemen tıklayın</a>
        <p>Hesabınız askıya alındı. Son uyarı.</p>
        <p>Kimliğinizi onaylayın — hesabınız kapatılacak.</p>
        <p>24 saat içinde işlem yapın.</p>
        </body></html>
    """)
    return make_email(
        subject=" Bu işlem size mi ait?",
        from_addr="security@totally-fake-bank.xyz",
        body_html=html,
    )


def make_clean_email() -> bytes:
    return make_email(
        subject="Haftalık Proje Raporu",
        from_addr="colleague@company.com",
        body_text="Merhaba, raporu ekteki belgede bulabilirsiniz. İyi çalışmalar.",
        dkim_signature="v=1; a=rsa-sha256; d=company.com; s=mail; b=fakesig",
    )


def make_suspicious_email() -> bytes:
    text = "Acil: hesabınızda güvenlik ihlali tespit edildi. Lütfen destek ekibiyle iletişime geçin."
    return make_email(
        subject="[Acil] Güvenlik Bildirimi",
        from_addr="alerts@some-service.com",
        body_text=text,
    )


@pytest.fixture(autouse=True)
def mock_external_calls(mocker):
    mocker.patch(
        "dns.resolver.resolve",
        side_effect=Exception("DNS: bağlantı yok (test modu)"),
    )

    mock_resp = MagicMock()
    mock_resp.url = "https://example.com/fake-destination"
    mocker.patch("requests.head", return_value=mock_resp)

    mock_vt = MagicMock()
    mock_vt.status_code = 200
    mock_vt.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                }
            }
        }
    }
    mocker.patch("requests.get", return_value=mock_vt)

    mock_us = MagicMock()
    mock_us.status_code = 200
    mock_us.json.return_value = {"uuid": "fake-uuid-1234"}
    mocker.patch("requests.post", return_value=mock_us)


class TestCalculateRisk:

    def _import(self):
        from detector import calculate_risk
        return calculate_risk

    def test_all_zero_returns_pass(self):
        calculate_risk = self._import()
        result = calculate_risk(
            {"header_risk_score": 0},
            {"content_risk_score": 0},
            {"url_risk_score": 0},
        )
        assert result["verdict"] == "PASS"
        assert result["final_risk_score"] == 0

    def test_high_scores_return_quarantine(self):
        calculate_risk = self._import()
        result = calculate_risk(
            {"header_risk_score": 75},
            {"content_risk_score": 40},
            {"url_risk_score": 50},
        )
        assert result["verdict"] == "QUARANTINE"
        assert result["final_risk_score"] >= 60

    def test_medium_scores_return_warn(self):
        calculate_risk = self._import()
        result = calculate_risk(
            {"header_risk_score": 50},
            {"content_risk_score": 20},
            {"url_risk_score": 0},
        )
        assert result["verdict"] == "WARN"
        assert 35 <= result["final_risk_score"] <= 59

    def test_score_capped_at_100(self):
        calculate_risk = self._import()
        result = calculate_risk(
            {"header_risk_score": 999},
            {"content_risk_score": 999},
            {"url_risk_score": 999},
        )
        assert result["final_risk_score"] <= 100

    def test_breakdown_keys_present(self):
        calculate_risk = self._import()
        result = calculate_risk(
            {"header_risk_score": 30},
            {"content_risk_score": 20},
            {"url_risk_score": 10},
        )
        assert "header" in result["breakdown"]
        assert "content" in result["breakdown"]
        assert "url" in result["breakdown"]

    def test_weight_formula_correctness(self):
        calculate_risk = self._import()
        result = calculate_risk(
            {"header_risk_score": 60},
            {"content_risk_score": 20},
            {"url_risk_score": 0},
        )
        assert result["final_risk_score"] == 40
        assert result["verdict"] == "WARN"

    def test_url_has_full_weight(self):
        calculate_risk = self._import()
        result = calculate_risk(
            {"header_risk_score": 0},
            {"content_risk_score": 0},
            {"url_risk_score": 50},
        )
        assert result["final_risk_score"] == 50
        assert result["verdict"] == "WARN"


class TestAnalyzeContent:

    def _import(self):
        from detector import analyze_content
        return analyze_content

    def test_clean_email_zero_score(self):
        analyze_content = self._import()
        raw = make_clean_email()
        result = analyze_content(raw)
        assert result["content_risk_score"] == 0
        assert result["found_keywords"] == []

    def test_single_keyword_adds_10_points(self):
        analyze_content = self._import()
        raw = make_email(body_text="acil işlem gerekiyor")
        result = analyze_content(raw)
        assert "acil" in result["found_keywords"]
        assert result["content_risk_score"] == 10

    def test_multiple_keywords_accumulate(self):
        analyze_content = self._import()
        raw = make_email(
            body_text="acil! hesabınız askıya alındı. hemen tıklayın!"
        )
        result = analyze_content(raw)
        assert result["content_risk_score"] >= 30

    def test_score_capped_at_40(self):
        analyze_content = self._import()
        text = " ".join([
            "hemen tıklayın", "işlem size mi ait", "hesabınız askıya alındı",
            "acil", "doğrulayın", "kimliğinizi onaylayın", "şüpheli işlem",
            "son uyarı", "hesabınız kapatılacak", "güvenlik ihlali",
            "verify your account", "security alert", "unauthorized access",
        ])
        raw = make_email(body_text=text)
        result = analyze_content(raw)
        assert result["content_risk_score"] == 40

    def test_urgency_pattern_24_saat(self):
        analyze_content = self._import()
        raw = make_email(body_text="24 saat içinde işleminizi tamamlayın.")
        result = analyze_content(raw)
        assert result["urgency_pattern_hits"] >= 1

    def test_html_body_parsed_correctly(self):
        analyze_content = self._import()
        html = "<html><body><p>hesabınız askıya alındı</p></body></html>"
        raw = make_email(body_html=html)
        result = analyze_content(raw)
        assert "hesabınız askıya alındı" in result["found_keywords"]

    def test_case_insensitive_matching(self):
        analyze_content = self._import()
        raw = make_email(body_text="hemen tıklayın ve işlemi doğrulayın")
        result = analyze_content(raw)
        assert "hemen tıklayın" in result["found_keywords"]
        assert result["content_risk_score"] >= 20

    def test_ascii_uppercase_matching(self):
        analyze_content = self._import()
        raw = make_email(body_text="SECURITY ALERT: VERIFY YOUR ACCOUNT NOW")
        result = analyze_content(raw)
        assert "security alert" in result["found_keywords"]
        assert "verify your account" in result["found_keywords"]

    def test_english_keywords_detected(self):
        analyze_content = self._import()
        raw = make_email(body_text="Verify your account immediately. Security alert!")
        result = analyze_content(raw)
        assert "verify your account" in result["found_keywords"]
        assert "security alert" in result["found_keywords"]


class TestExtractUrls:

    def _import(self):
        from detector import extract_urls
        return extract_urls

    def test_no_urls_returns_empty(self):
        extract_urls = self._import()
        raw = make_email(body_text="Herhangi bir link yok.")
        assert extract_urls(raw) == []

    def test_href_in_anchor_extracted(self):
        extract_urls = self._import()
        html = '<html><body><a href="https://evil.example.com/login">Tıkla</a></body></html>'
        raw = make_email(body_html=html)
        urls = extract_urls(raw)
        assert any("evil.example.com" in u for u in urls)

    def test_bitly_url_detected(self):
        extract_urls = self._import()
        html = '<a href="https://bit.ly/3xPhishTest">Hemen tıklayın</a>'
        raw = make_email(body_html=html)
        urls = extract_urls(raw)
        assert any("bit.ly" in u for u in urls)

    def test_plain_text_url_detected(self):
        extract_urls = self._import()
        raw = make_email(body_text="Şuraya gidin: https://forms.gle/fakelink")
        urls = extract_urls(raw)
        assert any("forms.gle" in u for u in urls)

    def test_multiple_urls_all_extracted(self):
        extract_urls = self._import()
        html = textwrap.dedent("""\
            <html><body>
            <a href="https://link1.com">Link 1</a>
            <a href="https://link2.com">Link 2</a>
            <a href="https://link3.com">Link 3</a>
            </body></html>
        """)
        raw = make_email(body_html=html)
        urls = extract_urls(raw)
        assert len(urls) >= 3

    def test_non_http_urls_ignored(self):
        extract_urls = self._import()
        html = '<a href="mailto:test@example.com">Mail</a>'
        raw = make_email(body_html=html)
        urls = extract_urls(raw)
        assert not any("mailto:" in u for u in urls)


class TestHeaderAnalysis:

    def test_missing_dkim_adds_risk(self):
        from detector import check_dkim, parse_email
        raw = make_email(body_text="test", dkim_signature="")
        msg = parse_email(raw)
        result = check_dkim(msg)
        assert result["pass"] is False
        assert result["risk"] == 25

    def test_present_dkim_zero_risk(self):
        from detector import check_dkim, parse_email
        raw = make_email(body_text="test", dkim_signature="v=1; a=rsa-sha256; b=fakesig")
        msg = parse_email(raw)
        result = check_dkim(msg)
        assert result["pass"] is True
        assert result["risk"] == 0

    def test_dns_failure_spf_adds_risk(self, mocker):
        from detector import check_spf
        result = check_spf("nonexistent-domain-xyz.com")
        assert result["pass"] is False
        assert result["risk"] > 0

    def test_dns_failure_dmarc_adds_risk(self, mocker):
        from detector import check_dmarc
        result = check_dmarc("nonexistent-domain-xyz.com")
        assert result["pass"] is False
        assert result["risk"] > 0

    def test_header_risk_capped_at_75(self):
        from detector import analyze_headers
        raw = make_email(from_addr="fake@nonexistent-xyz.com")
        result = analyze_headers(raw)
        assert result["header_risk_score"] <= 75


class TestEndToEndScenarios:

    def test_scenario_1_clean_email_passes(self):
        from detector import analyze_email
        raw = make_clean_email()
        result = analyze_email(raw)

        assert result["verdict"] == "PASS"
        assert result["risk_score"] < 35, (
            f"Temiz e-posta PASS çıkmalıydı ama skor {result['risk_score']}"
        )

    def test_scenario_2_suspicious_email_warns(self):
        from detector import analyze_email
        raw = make_suspicious_email()
        result = analyze_email(raw)

        assert result["verdict"] == "WARN", (
            f"Şüpheli e-posta WARN çıkmalıydı — "
            f"verdict={result['verdict']}, skor={result['risk_score']}"
        )
        assert 35 <= result["risk_score"] <= 59

    def test_scenario_3_phishing_quarantined(self):
        from detector import analyze_email
        raw = make_phishing_email()
        result = analyze_email(raw)

        content_score = result["details"]["content"]["content_risk_score"]
        assert content_score == 40, (
            f"Phishing e-postasında içerik skoru 40 olmalıydı, {content_score} çıktı"
        )

        header_score = result["details"]["header"]["header_risk_score"]
        assert header_score >= 60, (
            f"Header skoru ≥ 60 olmalıydı, {header_score} çıktı"
        )

        assert result["risk_score"] >= 50, (
            f"Phishing e-postası skor ≥ 50 olmalıydı, {result['risk_score']} çıktı"
        )

        assert result["verdict"] in ("WARN", "QUARANTINE"), (
            f"Phishing e-postası WARN veya QUARANTINE çıkmalıydı, "
            f"{result['verdict']} çıktı (skor: {result['risk_score']})"
        )

    def test_scenario_3_with_url_risk_quarantines(self):
        from unittest.mock import patch
        from detector import analyze_email

        raw = make_phishing_email()

        fake_url_result = {
            "total_urls_found": 2,
            "analyzed_urls": [],
            "url_risk_score": 40,
        }
        with patch("detector.analyze_urls", return_value=fake_url_result):
            result = analyze_email(raw)

        assert result["verdict"] == "QUARANTINE"
        assert result["risk_score"] >= 60

    def test_report_structure_complete(self):
        from detector import analyze_email
        raw = make_phishing_email()
        result = analyze_email(raw)

        required_keys = [
            "analyzed_at", "verdict", "action",
            "risk_score", "breakdown", "details",
        ]
        for key in required_keys:
            assert key in result, f"Raporda '{key}' alanı eksik"

    def test_report_details_has_all_modules(self):
        from detector import analyze_email
        raw = make_clean_email()
        result = analyze_email(raw)

        assert "header" in result["details"]
        assert "content" in result["details"]
        assert "urls" in result["details"]

    def test_score_increases_with_more_keywords(self):
        from detector import analyze_email

        few_kw = make_email(body_text="acil")
        many_kw = make_email(
            body_text=(
                "acil hesabınız askıya alındı. "
                "hemen tıklayın. son uyarı. "
                "güvenlik ihlali tespit edildi."
            )
        )

        r_few = analyze_email(few_kw)
        r_many = analyze_email(many_kw)

        assert r_many["risk_score"] > r_few["risk_score"], (
            "Daha fazla keyword daha yüksek skor üretmeli"
        )


class TestEdgeCases:

    def test_empty_email_does_not_crash(self):
        from detector import analyze_email
        raw = make_email()
        result = analyze_email(raw)
        assert "verdict" in result

    def test_very_long_body_handled(self):
        from detector import analyze_content
        long_body = "Bu normal bir metin. " * 5000
        raw = make_email(body_text=long_body)
        result = analyze_content(raw)
        assert result["content_risk_score"] == 0
        assert result["found_keywords"] == []

    def test_missing_from_header_no_crash(self):
        from detector import analyze_headers
        from email.mime.text import MIMEText
        msg = MIMEText("test", "plain")
        raw = msg.as_bytes()
        result = analyze_headers(raw)
        assert "header_risk_score" in result

    def test_unicode_body_handled(self):
        from detector import analyze_content
        raw = make_email(body_text="Şüpheli işlem: hesabınızı koruyun! İşlem size mi ait?")
        result = analyze_content(raw)
        assert result["content_risk_score"] > 0
