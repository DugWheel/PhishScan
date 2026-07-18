# PhishScan

> **Cloud-based phishing email detection framework for Gmail that combines email authentication analysis, NLP and threat intelligence services to automatically detect, score and quarantine phishing emails.**
>
> PhishScan analyzes incoming emails before they reach users, detects phishing attempts using a multi-layer detection engine, quarantines malicious messages, and sends Telegram notifications only for confirmed threats.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-79%20Passed-brightgreen)
![Telegram](https://img.shields.io/badge/Telegram-Bot-blue?logo=telegram)

---
## 📚 Table of Contents

- Features
- Architecture
- Tech Stack
- Project Structure
- Quick Start
- Configuration
- Detection Engine
- Telegram Bot
- Testing
- Development Tools
- Deployment
- Security
- License

##  Features

- Multi-layer phishing detection engine
- SPF, DKIM and DMARC validation
- Email header analysis
- NLP-based phishing content detection
- URL reputation analysis using VirusTotal
- URLScan.io integration
- Intelligent phishing scoring system
- Automatic email quarantine
- Gmail API integration
- Telegram bot for remote monitoring
- Local machine learning classifier (TF-IDF + Logistic Regression)
- URL normalization and caching
- Background scanning with multi-threaded architecture
- Fully covered by automated unit tests

---

##  Architecture

```text
Incoming Email (Gmail API)
            │
            ▼
┌────────────────────────────────────┐
│     Whitelist Validation           │
└────────────────┬───────────────────┘
                 ▼
┌────────────────────────────────────┐
│ Module 1 — Header Analysis         │
│ SPF • DKIM • DMARC • Return-Path   │
├────────────────────────────────────┤
│ Module 2 — Content Analysis        │
│ NLP • Keywords • Regex             │
├────────────────────────────────────┤
│ Module 3 — URL Analysis            │
│ VirusTotal • URLScan               │
├────────────────────────────────────┤
│        Decision Engine             │
└───────┬───────────────┬────────────┘
        │               │
   QUARANTINE        WARNING
        │               │
        ▼               ▼
 Telegram Alert     Log Only
 ```

---

## 🛠 Tech Stack

| Category | Technology |
|----------|------------|
| Language | Python 3.11+ |
| Email Processing | email (stdlib) |
| HTML Parsing | BeautifulSoup4 |
| DNS | dnspython |
| Gmail | Google Gmail API |
| Machine Learning | scikit-learn |
| Threat Intelligence | VirusTotal API |
| URL Analysis | URLScan.io |
| Telegram | python-telegram-bot |
| Deployment | Linux VPS + systemd |
| Testing | pytest |


 ## 📁 Project Structure

```text
phishscan/
├── src/
│   ├── main.py                     # Application entry point
│   ├── detector.py                 # Detection engine
│   ├── gmail_integration.py        # Gmail API integration
│   ├── nlp_engine.py               # Local ML classifier
│   ├── sanitizer.py                # Sensitive data masking
│   └── telegram_controller.py      # Telegram bot commands
│
├── tests/
│   ├── test_detector.py
│   └── test_nlp_sanitizer.py
│
├── tools/
│   ├── phishing_simulator.py
│   └── spoofed_eml_generator.py
│
├── data/
│   ├── vt_cache.json
│   ├── scanned_ids.json
│   └── model/
│
├── output/
├── config.example.json
├── requirements.txt
├── requirements-nlp.txt
├── phishscan.service
└── README.md
```

---

# 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/phishscan.git
cd phishscan
```

### 2. Create a virtual environment

**Linux / macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

---

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Install the optional NLP dependencies if you want to enable the local machine learning classifier.

```bash
pip install -r requirements-nlp.txt
```

---

### 4. Create the configuration

```bash
cp config.example.json config.json
```

Configure at least the following fields:

| Configuration | Description |
|--------------|-------------|
| `virustotal_api_key` | VirusTotal API key |
| `telegram_bot_token` | Telegram bot token |
| `telegram_allowed_user_id` | Authorized Telegram user |
| `whitelist_domains` | Trusted domains |

---

### 5. Gmail Authentication

Enable the Gmail API in **Google Cloud Console**, create an **OAuth Desktop Client**, and place the downloaded credentials file in the project root as:

```text
credentials.json
```

Run the authentication process:

```bash
python src/gmail_integration.py
```

After successful authentication, a `token.json` file will be generated automatically.

---

### 6. Run PhishScan

```bash
python src/main.py
```

The scanner will start monitoring unread Gmail messages in the background.

---

##  Configuration

The application is configured using `config.json`.

| Key | Description |
|-----|-------------|
| `scan_interval` | Scan interval (seconds) |
| `scan_max_results` | Maximum emails per scan |
| `whitelist_domains` | Trusted domains |
| `quarantine_label` | Gmail quarantine label |
| `virustotal_api_key` | VirusTotal API key |
| `urlscan_api_key` | URLScan API key |
| `telegram_bot_token` | Telegram Bot token |
| `telegram_allowed_user_id` | Authorized Telegram user |
| `nlp_provider` | disabled / local / remote_api |

> **Recommended:** Use `local` for privacy-focused deployments. All NLP processing stays on your machine.

---

#  Detection Engine

PhishScan uses a **multi-layer scoring engine** to identify phishing emails. Instead of relying on a single indicator, multiple independent analyses contribute to a final risk score.

## Detection Pipeline

| Module | Purpose |
|---------|---------|
| Header Analysis | Validates SPF, DKIM, DMARC and Return-Path |
| Content Analysis | Detects phishing language using keywords, regex and NLP |
| URL Analysis | Checks links with VirusTotal and URLScan.io |
| Decision Engine | Calculates the final risk score and determines the action |

---

## Header Analysis

The header analyzer inspects common email authentication mechanisms.

Checks include:

- SPF validation
- DKIM signature verification
- DMARC policy validation
- Return-Path consistency
- Trusted Email Service Provider detection

Common providers such as **Google Workspace**, **Microsoft 365**, **Amazon SES**, **Mailchimp**, and **SendGrid** are automatically recognized to reduce false positives.

---

## Content Analysis

The content analyzer evaluates the email body for phishing characteristics.

Detection includes:

- Urgency expressions
- Credential harvesting attempts
- Banking and payment scams
- Password reset fraud
- Social engineering language
- Turkish and English phishing keywords
- Regular expression based pattern matching

---

## URL Analysis

To reduce unnecessary API requests, URL reputation checks are only performed for suspicious emails.

```text
Score < 15
      │
      └── Skip URL analysis

15 ≤ Score ≤ 80
      │
      └── VirusTotal + URLScan

Score > 80
      │
      └── Already malicious
```

Features:

- URL normalization
- Tracking parameter removal
- VirusTotal cache
- URLScan screenshot support
- Duplicate request prevention

---

## Decision Engine

Each module contributes to the final phishing score.

```text
Final Score

(Header × 0.5)
+
(Content × 0.5)
+
(URL × 1.0)
```

| Score | Action |
|--------|--------|
| **0–34** | Clean |
| **35–59** | Warning |
| **60+** | Quarantine |

Only **Quarantine** events trigger Telegram notifications.

---

## Local Machine Learning

An optional **TF-IDF + Logistic Regression** classifier provides a second opinion for borderline cases.

The classifier:

- Runs locally
- Never overrides obvious malicious emails
- Never overrides clearly legitimate emails
- Is only used for uncertain classifications

This approach improves accuracy while keeping false positives low.

---
---

# 📱 Telegram Bot

PhishScan includes a built-in Telegram bot for remote monitoring and basic system control.

## Supported Commands

| Command | Description |
|---------|-------------|
| `/status` | Display scanner status and statistics |
| `/startscan` | Resume email scanning |
| `/stopscan` | Pause email scanning |
| `/threats` | Show the latest quarantined emails |
| `/help` | Display available commands |

## Notification Policy

To minimize notification fatigue, Telegram alerts are sent **only** when an email is classified as **Quarantine**.

Example notification:

```text
🚨 Phishing Email Blocked

Subject : Is this transaction yours?
Sender  : noreply@suspicious-bank.xyz
Risk    : 85/100
Action  : Quarantined
Time    : 2026-07-16 21:00 UTC
```

---

#  Testing

PhishScan includes automated unit tests covering the detection engine, NLP components and utility modules.

Run all tests:

```bash
pytest tests/ -v
```

Run a specific test file:

```bash
pytest tests/test_detector.py -v
```

Run a specific test class:

```bash
pytest tests/test_nlp_sanitizer.py::TestSanitizer -v
```

Current test status:

- ✅ 79 unit tests
- ✅ Offline execution
- ✅ Mocked external services
- ✅ No Gmail account required

---

#  Development Tools

The project includes helper utilities for testing different phishing scenarios.

| Tool | Purpose |
|------|---------|
| `phishing_simulator.py` | Sends realistic phishing scenarios using Gmail SMTP |
| `spoofed_eml_generator.py` | Generates spoofed `.eml` files without sending emails |

Example:

```bash
python tools/phishing_simulator.py --scenario all
```

Generate spoofed emails:

```bash
python tools/spoofed_eml_generator.py --scenario bank
```

---

#  Deployment

PhishScan is designed for long-running environments.

Recommended deployment:

- Linux VPS
- Python 3.11+
- systemd service
- Gmail API
- Telegram Bot API

Typical deployment workflow:

```bash
git clone https://github.com/YOUR_USERNAME/phishscan.git
cd phishscan

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
python src/main.py
```

Production deployments can be managed using the included `phishscan.service` file.

---

#  Security

Before running PhishScan in production, consider the following recommendations:

- Never whitelist public email providers such as `gmail.com` or `outlook.com`.
- Restrict Telegram bot access using `telegram_allowed_user_id`.
- Keep API keys outside version control.
- Rotate credentials regularly.
- Use the local NLP provider whenever possible to maximize privacy.
- Protect `config.json`, `credentials.json` and `token.json`.


---

# 📄 License

This project is licensed under the **MIT License**.

See the [LICENSE](LICENSE) file for details.

---
