# 🤖 AI SOC Agent: Wazuh × Telegram × AI Automation

<p align="center">
  <a href="README.md">English</a> &bull;
  <a href="README_fr.md">Français</a>
</p>

```
 █████╗  ██████╗ ███████╗███╗   ██╗████████╗    ██╗ █████╗     ███████╗ ██████╗  ██████╗
██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝    ██║██╔══██╗    ██╔════╝██╔═══██╗██╔════╝
███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║       ██║███████║    ███████╗██║   ██║██║
██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║       ██║██╔══██║    ╚════██║██║   ██║██║
██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║       ██║██║  ██║    ███████║╚██████╔╝╚██████╗
╚═╝  ╚═╝ ╚═════╝ ╚════════╝╚═╝  ╚═══╝   ╚═╝       ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝  ╚═════╝
```

> **A defensive SOC agent. It receives Wazuh alerts, analyses them (LLM or heuristic), logs or executes the action permitted by the configuration, then requests a human decision on Telegram or in the dashboard. Automatic remediation is disabled by default.**

## ⚠️ What is implemented vs what is a prototype

To stay honest about the maturity level of the repository, the features are classified into two categories:

**✅ Effective (working and tested code)**
- `/webhook/wazuh` webhook + web dashboard (stats, log, history and decisions).
- Alert analysis via the **DeepSeek API**, with automatic fallback to an offline **heuristic** engine.
- Human decision on **Telegram** (APPROVE / REJECT / UNSURE) + equivalent endpoints on the dashboard, notably for Wazuh rule proposals.
- IP blocking via **iptables** (`block_ip`, `block_ip_temporary` with scheduled unblocking after 1 h).
- **Slack** notification if a webhook is provided.
- **False positive** detection and generation of Wazuh silence rules.
- Action log in `alerts_log.json`, pending approvals in `pending_approvals.json`.

**🔬 Prototypes / to be connected (planned structure, not yet wired up)**
- **Disabling an Active Directory account**: the command `net user … /active:no` is defined in `config.py` but is **not executed** by the remediation engine.
- **Creation of a real GLPI ticket**: the code logs "Ticket to create" but **does not call the GLPI API**; `GLPI_URL` / `GLPI_API_TOKEN` still have to be wired up.

> Automatic remediation is **disabled by default** (`SOC_ENABLE_AUTO_REMEDIATION` variable). Without this variable set to `true`, the engine records the action but does not execute it.

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.x-0077B5?logo=wazuh&logoColor=white)](https://wazuh.com)
[![Telegram](https://img.shields.io/badge/Telegram-Bot-26A5E4?logo=telegram&logoColor=white)](https://core.telegram.org/bots)
[![Tests](https://img.shields.io/badge/Tests-11%2F11%20✓-green)](tests/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🎯 The problem

N1 SOC analysts regularly have to:
- Sort through **false positives** and legitimate events
- **Copy and paste** IPs into blocking tools
- Document and then get sensitive decisions validated

These repetitive tasks slow down processing and divert attention from priority incidents.

## 💡 The solution

**AI SOC Agent** helps close the loop, from detection to decision, by reducing the time spent sorting through noise. The webhook normalises the alert, the engine analyses it, then logs or executes the action according to the configuration. Telegram and the dashboard then provide human validation for rule proposals and sensitive decisions.

---

## 🏗️ Architecture

![Actual architecture of the AI SOC Agent](assets/architecture.svg)

The engine tries DeepSeek when a key is available, then falls back to local rules. Automatic remediation remains **disabled by default**: without `SOC_ENABLE_AUTO_REMEDIATION=true`, no IP block proposed by the analysis is executed. The AD and GLPI integrations remain outside the effective flow.

---

## ⚡ Quick Start

```bash
# 1. Clone
git clone https://github.com/Yukouf/agent-ia-soc.git && cd agent-ia-soc

# 2. Dependencies
pip install flask requests

# 3. Configure Telegram
export TELEGRAM_BOT_TOKEN="votre_token"
export TELEGRAM_CHAT_IDS='["ID_CHAT_1","ID_CHAT_2"]'

# 4. Run
python3 webhook_receiver.py
```

```
╔══════════════════════════════════════════╗
║   🤖 AI SOC Agent (Automatic)            ║
║                                          ║
║   Dashboard: http://0.0.0.0:5000         ║
║   Webhook:   POST /webhook/wazuh         ║
║   Test:      GET  /webhook/test          ║
╚══════════════════════════════════════════╝
```

---

## 🧠 How it works

### 1. Wazuh alert → Webhook

Wazuh sends its alerts to the `/webhook/wazuh` webhook:

```json
{
  "rule": {
    "id": "100002",
    "level": 10,
    "description": "Bruteforce SSH detected from 192.168.1.100"
  },
  "data": {
    "srcip": "192.168.1.100",
    "srcuser": "root"
  }
}
```

### 2. Analysis by AI

`ai_engine.py` analyses the alert and returns:

```json
{
  "severity": "high",
  "confidence": 92,
  "explanation": "15 SSH attempts in 30 seconds from an unknown external IP. No legitimate reason.",
  "suggested_action": "block_ip",
  "is_false_positive": false
}
```

### 3. Human validation on Telegram

> ⚠️ **ALERT #100002: BRUTEFORCE SSH**
> IP: `192.168.1.100` | Agent: `srv-web-01`
> **Suggested action:** `block_ip`
>
> [✅ APPROVE] [❌ REJECT] [❓ UNSURE]

### 4. Remediation

If approved **and** if automatic remediation is enabled (`SOC_ENABLE_AUTO_REMEDIATION=true`), `remediation_engine.py` executes:

| Action | State | Behaviour |
|---|---|---|
| `block_ip` | ✅ effective | `iptables -A INPUT -s IP -j DROP` |
| `block_ip_temporary` | ✅ effective | 1 h block then automatic removal |
| `silence_alert` | ✅ effective | Records the false positive + Wazuh silence rule |
| `notify_slack` | ✅ effective | Slack alert (if webhook provided) |
| `verify_and_escalate` | ✅ effective | Escalation to the human (log + Slack) |
| `create_ticket` | ⚠️ partial | Logs "Ticket to create". The GLPI API call still has to be wired up |
| `disable_user_ad` | 🔬 prototype | Defined in `config.py`, **not executed** by the engine |

> **Important:** if automatic remediation is disabled (the default setting), these actions are **recorded in the log** but **never executed**: human validation remains mandatory.

---

## 📊 Web dashboard

Minimal server-rendered interface, with client-side JavaScript limited to auto-refresh and approval actions:

- 🔴 **Active alerts** with severity and confidence
- 📋 **History** of remediations
- 📈 **Statistics** (false positives, executed actions)
- 🔍 **Detail** per alert

---

## 🧪 Tests

```bash
python3 -m unittest discover -s tests -v
```

```
test_auto_remediation_is_disabled_by_default ... ok
test_xss_telegram_approve ...................... ok
test_xss_telegram_reject ....................... ok
test_xss_telegram_unsure ....................... ok
test_xss_dashboard_approve ..................... ok
test_xss_dashboard_reject ...................... ok
test_xss_dashboard_unsure ...................... ok
test_xss_payload_escape ........................ ok
test_fp_tracker_integrity ...................... ok
test_pending_approvals_integrity ............... ok
test_security_headers .......................... ok

Ran 11 tests in 0.024s: OK
```

---

## 🔒 Security

- ✅ HTML escaping of all untrusted data (XSS)
- ✅ Client-side JavaScript limited to refresh and dashboard decisions
- ✅ Validation of incoming payloads
- ✅ Automated security tests
- ✅ False positive detection, rule proposals and deployment after approval

---

## 📁 Structure

```
agent-ia-soc/
├── webhook_receiver.py    # Flask server + dashboard + endpoints
├── ai_engine.py            # AI analysis of alerts
├── remediation_engine.py   # Execution of actions
├── telegram_bot.py         # Telegram bot (polling + notifications)
├── wazuh_rule_manager.py   # Wazuh silence rule management
├── sample_alerts.py        # Test alert set
├── config.py               # Centralised configuration
├── test_fp.py              # False positive test
├── tests/
│   └── test_security.py    # 11 security tests
├── assets/architecture.svg # Vector architecture diagram
├── alerts_log.json         # Log of processed alerts (generated at runtime)
├── fp_tracker.json         # False positive tracker (generated at runtime)
└── pending_approvals.json  # Pending approvals (generated at runtime)
```

---

## 🛣️ Roadmap

- [ ] Native Discord integration (in addition to Telegram)
- [x] Automatic false positive detection
- [x] Lightweight dashboard with client-side refresh and decisions
- [ ] Advanced remediation playbooks (SOAR)
- [ ] Multi-tenant support
- [ ] PDF export of incident reports

---

## ⚖️ License

MIT, do what you want with it. Fork, improve, deploy. Just credit the author.

---

*Built with ❤️‍🔥 by [Youssef Guerniou](https://github.com/Yukouf), because SOCs deserve better than copy and paste.*
