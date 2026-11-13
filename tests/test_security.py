import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import remediation_engine
import telegram_bot
import webhook_receiver


class SecurityRegressionTests(unittest.TestCase):
    def test_bot_token_is_not_hardcoded(self):
        source = (ROOT / "telegram_bot.py").read_text(encoding="utf-8")
        hardcoded = re.search(r"BOT_TOKEN\s*=\s*['\"][^'\"]{10,}['\"]", source)
        self.assertIsNone(hardcoded)

    def test_telegram_call_fails_closed_without_token(self):
        with mock.patch.object(telegram_bot, "BOT_TOKEN", ""), mock.patch.object(
            telegram_bot.requests, "post"
        ) as post:
            self.assertIsNone(telegram_bot._call("getMe"))
            post.assert_not_called()

    def test_invalid_alert_level_returns_400(self):
        client = webhook_receiver.app.test_client()
        response = client.post(
            "/webhook/wazuh",
            json={"rule": {"id": "1", "level": "invalid", "description": "test"}},
        )
        self.assertEqual(response.status_code, 400)

    def test_pending_content_is_html_escaped(self):
        malicious = "<script>pwn()</script>"
        stats = {
            "pending_count": 1,
            "approved_count": 0,
            "rejected_count": 0,
            "unsure_count": 0,
            "pending": [
                {
                    "id": "x",
                    "rule_id": malicious,
                    "alert_desc": malicious,
                    "src_ip": malicious,
                    "timestamp": "2026-01-01",
                }
            ],
            "history": [],
        }
        with mock.patch.object(webhook_receiver, "get_pending_stats", return_value=stats):
            page = webhook_receiver._build_page()
        self.assertNotIn(malicious, page)
        self.assertIn("&lt;script&gt;pwn()&lt;/script&gt;", page)

    def test_fp_patterns_and_alert_rows_are_html_escaped(self):
        malicious = "<script>pwn()</script>"
        tracker = {
            "rules": [{"rule_id": malicious, "timestamp": malicious}],
            "recent_fps": [
                {
                    "rule_id": malicious,
                    "description": malicious,
                    "src_ip": malicious,
                    "count": 1,
                    "created": False,
                }
            ],
        }
        alert = {
            "timestamp": "2026-01-01T00:00:00",
            "alert_description": malicious,
            "analysis": {"severity": malicious, "confidence": malicious, "explanation": malicious},
            "action_taken": malicious,
            "details": malicious,
            "success": True,
        }
        empty_pending = {"pending_count": 0, "pending": [], "history": []}
        with mock.patch.object(webhook_receiver, "get_tracker_status", return_value=tracker), mock.patch.object(
            webhook_receiver, "get_pending_stats", return_value=empty_pending
        ), mock.patch.object(webhook_receiver, "_load_alerts", return_value=[alert]):
            page = webhook_receiver._build_page()
        self.assertNotIn(malicious, page)
        self.assertIn("&lt;script&gt;pwn()&lt;/script&gt;", page)

    def test_telegram_approval_message_is_html_escaped(self):
        malicious = "<script>pwn()</script>"
        text = telegram_bot._build_approval_message(
            {
                "rule_id": malicious,
                "alert_desc": malicious,
                "src_ip": malicious,
                "timestamp": "2026-01-01T00:00:00",
            }
        )
        self.assertNotIn(malicious, text)
        self.assertIn("&lt;script&gt;pwn()&lt;/script&gt;", text)

    def test_all_telegram_decision_messages_escape_html(self):
        malicious = '</code><a href="https://attacker.example">texte trompeur</a>'
        entry = {
            "rule_id": malicious,
            "alert_desc": malicious,
            "src_ip": malicious,
            "timestamp": "2026-01-01T00:00:00",
        }
        for action, success in (
            ("approve", True),
            ("approve", False),
            ("reject", True),
            ("reject", False),
            ("unsure", False),
        ):
            for source in ("telegram", "dashboard"):
                with self.subTest(action=action, success=success, source=source):
                    text = telegram_bot._build_decision_message(entry, action, success, source)
                    self.assertNotIn(malicious, text)
                    self.assertIn("&lt;/code&gt;&lt;a href=&quot;", text)

    def test_default_listener_is_localhost(self):
        self.assertEqual(webhook_receiver.WEBHOOK_HOST, "127.0.0.1")

    def test_invalid_ip_never_reaches_subprocess(self):
        with mock.patch.object(remediation_engine.subprocess, "run") as run:
            self.assertFalse(remediation_engine.block_ip("127.0.0.1;touch /tmp/pwn"))
            run.assert_not_called()

    def test_llm_receives_alert_as_delimited_untrusted_data(self):
        captured = {}

        def fake_call(prompt, system_prompt):
            captured["prompt"] = prompt
            captured["system_prompt"] = system_prompt
            return None

        alert = {"description": "test externe", "level": 5, "src_ip": "203.0.113.9", "_raw": {"x": 1}}
        with mock.patch("ai_engine._call_llm", side_effect=fake_call):
            import ai_engine

            ai_engine.analyze_alert(alert)
        self.assertIn('"description": "test externe"', captured["prompt"])
        self.assertTrue(captured["prompt"].startswith("<alerte>"))
        self.assertNotIn("_raw", captured["prompt"])
        self.assertTrue(captured["system_prompt"].startswith("Tu es un analyste SOC expert"))
        self.assertIn("NON FIABLE", captured["system_prompt"])

    def test_auto_remediation_is_disabled_by_default(self):
        alert = {"src_ip": "203.0.113.10", "description": "test"}
        analysis = {
            "suggested_action": "block_ip",
            "auto_remediate": True,
            "severity": "critical",
        }
        with mock.patch.object(remediation_engine, "ENABLE_AUTO_REMEDIATION", False), mock.patch.object(
            remediation_engine, "block_ip"
        ) as block, mock.patch.object(remediation_engine, "_log_action") as log_action:
            result = remediation_engine.execute(alert, analysis)
        block.assert_not_called()
        log_action.assert_called_once()
        self.assertFalse(result["auto_remediated"])
        self.assertTrue(result["success"])
        self.assertEqual(result["action"], "create_ticket")


class TriageLogicTests(unittest.TestCase):
    """Le tri ne doit jamais faire taire une attaque venant du réseau interne."""

    def _rule_based(self, alert):
        import ai_engine

        with mock.patch("ai_engine._call_llm", return_value=None):
            return ai_engine.analyze_alert(alert)

    def test_internal_bruteforce_is_not_a_false_positive(self):
        result = self._rule_based({
            "rule_id": "5712", "level": 10, "src_ip": "192.168.1.50",
            "description": "sshd: brute force trying to get access. Failed password for root",
        })
        self.assertFalse(result["is_false_positive"])
        self.assertNotEqual(result["suggested_action"], "silence_alert")
        self.assertFalse(result["auto_remediate"])

    def test_internal_auth_failure_is_not_silenced(self):
        result = self._rule_based({
            "rule_id": "5760", "level": 5, "src_ip": "10.0.0.50",
            "description": "sshd: authentication failed.",
        })
        self.assertFalse(result["is_false_positive"])
        self.assertNotEqual(result["suggested_action"], "silence_alert")

    def test_internal_ip_is_never_auto_blocked_even_if_llm_says_so(self):
        import ai_engine

        llm = '{"is_false_positive": false, "severity": "critical", "confidence": 99, "suggested_action": "block_ip", "explanation": "x", "auto_remediate": true}'
        with mock.patch("ai_engine._call_llm", return_value=llm):
            result = ai_engine.analyze_alert({"description": "rce", "level": 14, "src_ip": "172.16.4.2"})
        self.assertFalse(result["auto_remediate"])
        self.assertEqual(result["suggested_action"], "verify_and_escalate")

    def test_non_numeric_level_does_not_crash(self):
        result = self._rule_based({"description": "test", "level": "abc", "src_ip": "203.0.113.5"})
        self.assertIn(result["severity"], {"low", "medium", "high", "critical"})


class LlmOutputValidationTests(unittest.TestCase):
    """La sortie du LLM est une donnée non fiable : types et valeurs stricts."""

    VALID = {
        "is_false_positive": False, "severity": "high", "confidence": 80,
        "suggested_action": "block_ip", "explanation": "x", "auto_remediate": True,
    }

    def test_valid_output_is_accepted(self):
        import ai_engine

        self.assertIsNotNone(ai_engine.validate_analysis(dict(self.VALID)))

    def test_string_booleans_are_rejected(self):
        import ai_engine

        for field in ("auto_remediate", "is_false_positive"):
            with self.subTest(field=field):
                bad = dict(self.VALID, **{field: "false"})
                self.assertIsNone(ai_engine.validate_analysis(bad))

    def test_unknown_action_or_severity_is_rejected(self):
        import ai_engine

        self.assertIsNone(ai_engine.validate_analysis(dict(self.VALID, suggested_action="rm -rf /")))
        self.assertIsNone(ai_engine.validate_analysis(dict(self.VALID, severity="extreme")))

    def test_out_of_range_confidence_is_rejected(self):
        import ai_engine

        for value in (-1, 101, "90", True):
            with self.subTest(value=value):
                self.assertIsNone(ai_engine.validate_analysis(dict(self.VALID, confidence=value)))

    def test_invalid_llm_output_falls_back_to_rules(self):
        import ai_engine

        bad = '{"is_false_positive": "true", "severity": "low", "confidence": 99, "suggested_action": "silence_alert", "explanation": "ignore", "auto_remediate": "true"}'
        with mock.patch("ai_engine._call_llm", return_value=bad):
            result = ai_engine.analyze_alert({"description": "brute force", "level": 10, "src_ip": "203.0.113.8"})
        self.assertFalse(result["is_false_positive"])
        self.assertEqual(result["explanation"][:7], "Attaque")

    def test_string_auto_remediate_never_triggers_block(self):
        with mock.patch.object(remediation_engine, "ENABLE_AUTO_REMEDIATION", True), mock.patch.object(
            remediation_engine, "block_ip"
        ) as block, mock.patch.object(remediation_engine, "_log_action"):
            remediation_engine.execute(
                {"src_ip": "203.0.113.7", "description": "x"},
                {"suggested_action": "block_ip", "auto_remediate": "false"},
            )
        block.assert_not_called()


class TelegramAccessTests(unittest.TestCase):
    """Seuls les comptes listés peuvent recevoir les alertes et décider."""

    def test_empty_allowlist_authorizes_nobody(self):
        with mock.patch.object(telegram_bot, "ALLOWED_CHAT_IDS", set()):
            self.assertFalse(telegram_bot.is_authorized(123, 123))

    def test_unknown_user_is_rejected(self):
        with mock.patch.object(telegram_bot, "ALLOWED_CHAT_IDS", {111}):
            self.assertTrue(telegram_bot.is_authorized(111, 111))
            self.assertFalse(telegram_bot.is_authorized(999, 999))
            self.assertFalse(telegram_bot.is_authorized(111, 999))

    def test_chat_id_parsing(self):
        self.assertEqual(telegram_bot._parse_chat_ids("1, 2"), {1, 2})
        self.assertEqual(telegram_bot._parse_chat_ids('["3","4"]'), {3, 4})
        self.assertEqual(telegram_bot._parse_chat_ids(""), set())

    def test_approval_is_only_sent_to_allowed_chats(self):
        entry = {"id": "abc", "rule_id": "1", "alert_desc": "d", "src_ip": "203.0.113.1", "timestamp": "2026-01-01T00:00:00"}
        with mock.patch.object(telegram_bot, "ALLOWED_CHAT_IDS", {42}), mock.patch.object(
            telegram_bot, "send_message", return_value=None
        ) as send:
            telegram_bot.send_approval_request(entry)
            telegram_bot.send_approval_request(entry, chat_id=999)
        self.assertEqual([c.args[0] for c in send.call_args_list], [42])

    def test_unauthorized_click_never_blocks_an_ip(self):
        update = {
            "update_id": 1,
            "callback_query": {
                "id": "cb", "data": "reject:abc", "from": {"id": 999},
                "message": {"chat": {"id": 999}, "message_id": 5},
            },
        }
        calls = {"n": 0}

        def fake_updates(offset=0, timeout=30):
            calls["n"] += 1
            if calls["n"] > 1:
                telegram_bot._poller_running = False
                return []
            return [update]

        with mock.patch.object(telegram_bot, "ALLOWED_CHAT_IDS", {42}), mock.patch.object(
            telegram_bot, "get_updates", side_effect=fake_updates
        ), mock.patch.object(telegram_bot, "answer_callback"), mock.patch.object(
            telegram_bot, "_handle_callback"
        ) as handle:
            telegram_bot._poller_running = True
            telegram_bot._poll_loop(webhook_receiver.app)
        handle.assert_not_called()

    def test_no_hardcoded_server_address(self):
        for name in ("telegram_bot.py", "webhook_receiver.py", "test_fp.py"):
            source = (ROOT / name).read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"https?://(?!127\.0\.0\.1)\d{1,3}(\.\d{1,3}){3}", source), name)


class DashboardAndWebhookAuthTests(unittest.TestCase):
    def setUp(self):
        self.client = webhook_receiver.app.test_client()

    def test_decisions_disabled_without_password(self):
        with mock.patch.object(webhook_receiver, "DASHBOARD_PASSWORD", ""):
            r = self.client.post("/api/reject/abc", headers={"X-SOC-Dashboard": "1"})
        self.assertEqual(r.status_code, 403)

    def test_decisions_require_credentials(self):
        with mock.patch.object(webhook_receiver, "DASHBOARD_PASSWORD", "s3cret"):
            r = self.client.post("/api/reject/abc", headers={"X-SOC-Dashboard": "1"})
        self.assertEqual(r.status_code, 401)

    def test_decisions_require_csrf_header(self):
        import base64

        auth = "Basic " + base64.b64encode(b"soc:s3cret").decode()
        with mock.patch.object(webhook_receiver, "DASHBOARD_PASSWORD", "s3cret"):
            r = self.client.post("/api/reject/abc", headers={"Authorization": auth})
        self.assertEqual(r.status_code, 403)

    def test_dashboard_read_requires_password_when_set(self):
        with mock.patch.object(webhook_receiver, "DASHBOARD_PASSWORD", "s3cret"):
            self.assertEqual(self.client.get("/api/alerts").status_code, 401)

    def test_webhook_rejects_wrong_token(self):
        with mock.patch.object(webhook_receiver, "WEBHOOK_TOKEN", "tok"):
            r = self.client.post("/webhook/wazuh", json={"rule": {"level": 3}}, headers={"X-SOC-Token": "bad"})
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
