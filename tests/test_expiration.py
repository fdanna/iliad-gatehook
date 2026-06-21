import importlib.util
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


admin = load_module("admin_server", ROOT / "admin" / "admin_server.py")
gatehook = load_module("gatehook", ROOT / "scripts" / "gatehook.py")
healthcheck = load_module("healthcheck", ROOT / "scripts" / "healthcheck.py")


def fake_response(payload, status=200):
    response = mock.MagicMock()
    response.status = status
    response.read.return_value = json.dumps(payload).encode("utf-8")
    response.__enter__.return_value = response
    return response


class AdminExpirationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        base = Path(self.tempdir.name)
        self.caller = "sip:3331234567@voip.iliad.it;user=phone"
        admin.WHITELIST_PATH = base / "whitelist.txt"
        admin.WHITELIST_TOGGLE_PATH = base / "whitelist.enabled"
        admin.METADATA_PATH = base / "whitelist_meta.json"
        admin.BACKUP_DIR = base / "backups"
        admin.LOCK_PATH = base / ".admin.lock"
        admin.ACCESS_LOG_PATH = base / "access.log"
        admin.SYSTEM_LOG_PATH = base / "system.log"
        admin.WHITELIST_PATH.write_text(self.caller + "\n", encoding="utf-8")
        admin.WHITELIST_TOGGLE_PATH.write_text("1\n", encoding="utf-8")

    def tearDown(self):
        self.tempdir.cleanup()

    def write_expiration(self, date_value, enabled=True):
        admin.METADATA_PATH.write_text(
            json.dumps(
                {
                    "entries": {
                        self.caller: {
                            "added_at": admin.utc_now_iso(),
                            "expiration_enabled": enabled,
                            "expires_on": date_value.isoformat(),
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

    def test_state_separates_active_expiring_caller(self):
        tomorrow = admin.datetime.now(admin.ROME_TZ).date() + timedelta(days=1)
        self.write_expiration(tomorrow)
        payload = admin.state()
        self.assertEqual([], payload["entries"])
        self.assertEqual(1, payload["expiring_entries"][0]["expiration"]["days_left"])
        self.assertEqual("Active", payload["expiring_entries"][0]["expiration"]["status"])

    def test_expired_caller_remains_visible_with_expired_status(self):
        yesterday = admin.datetime.now(admin.ROME_TZ).date() - timedelta(days=1)
        self.write_expiration(yesterday)
        expiration = admin.state()["expiring_entries"][0]["expiration"]
        self.assertTrue(expiration["expired"])
        self.assertEqual("Expired", expiration["status"])

    def test_disabling_expiration_returns_caller_to_permanent_list(self):
        tomorrow = admin.datetime.now(admin.ROME_TZ).date() + timedelta(days=1)
        self.write_expiration(tomorrow)
        payload = admin.set_expiration(self.caller, False)
        self.assertEqual(1, len(payload["entries"]))
        self.assertEqual([], payload["expiring_entries"])


class GatehookExpirationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.metadata_path = Path(self.tempdir.name) / "whitelist_meta.json"
        gatehook.METADATA_PATH = str(self.metadata_path)
        self.caller = "sip:3331234567@voip.iliad.it;user=phone"

    def tearDown(self):
        self.tempdir.cleanup()

    def test_expired_caller_is_rejected_before_gate_trigger(self):
        yesterday = gatehook.datetime.now(gatehook.ROME_TZ).date() - timedelta(days=1)
        self.metadata_path.write_text(
            json.dumps(
                {
                    "entries": {
                        self.caller: {
                            "expiration_enabled": True,
                            "expires_on": yesterday.isoformat(),
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        message = {
            "class": "call",
            "type": "CALL_INCOMING",
            "direction": "incoming",
            "param": {"peer": self.caller},
        }
        gatehook.last_trigger = float("-inf")
        with mock.patch.object(gatehook, "trigger_shelly") as trigger, mock.patch.object(
            gatehook, "send_hangup"
        ) as hangup, mock.patch.object(gatehook, "log_access") as access:
            gatehook.handle_message(mock.Mock(), message)
        trigger.assert_not_called()
        hangup.assert_called_once()
        access.assert_called_once_with("rejected", self.caller, "expired")


class GateReliabilityTests(unittest.TestCase):
    def setUp(self):
        gatehook.SHELLY_RETRIES = 3
        gatehook.SHELLY_RETRY_DELAY = 0.01

    def test_trigger_verifies_device_identity_before_activation(self):
        info = fake_response({"id": gatehook.SHELLY_EXPECTED_ID})
        triggered = fake_response({"was_on": False})
        with mock.patch.object(
            gatehook.urllib.request, "urlopen", side_effect=[info, triggered]
        ) as urlopen:
            self.assertTrue(gatehook.trigger_shelly())

        self.assertEqual(gatehook.SHELLY_INFO_URL, urlopen.call_args_list[0].args[0])
        request = urlopen.call_args_list[1].args[0]
        self.assertEqual(gatehook.SHELLY_URL, request.full_url)
        self.assertEqual({"id": 0, "on": True}, json.loads(request.data))

    def test_wrong_device_is_never_activated(self):
        responses = [fake_response({"id": "wrong-device"}) for _ in range(3)]
        with mock.patch.object(
            gatehook.urllib.request, "urlopen", side_effect=responses
        ) as urlopen, mock.patch.object(gatehook.time, "sleep"):
            self.assertFalse(gatehook.trigger_shelly())
        self.assertEqual(3, urlopen.call_count)
        self.assertTrue(
            all(call.args[0] == gatehook.SHELLY_INFO_URL for call in urlopen.call_args_list)
        )

    def test_transient_shelly_failure_is_retried(self):
        with mock.patch.object(
            gatehook.urllib.request,
            "urlopen",
            side_effect=[
                OSError("temporary failure"),
                fake_response({"id": gatehook.SHELLY_EXPECTED_ID}),
                fake_response({"was_on": False}),
            ],
        ), mock.patch.object(gatehook.time, "sleep") as sleep:
            self.assertTrue(gatehook.trigger_shelly())
        sleep.assert_called_once_with(gatehook.SHELLY_RETRY_DELAY)

    def test_failed_activation_is_not_logged_as_accepted(self):
        sock = mock.Mock()
        with mock.patch.object(gatehook, "trigger_shelly", return_value=False), mock.patch.object(
            gatehook, "log_access"
        ) as access, mock.patch.object(gatehook, "send_hangup") as hangup:
            gatehook.complete_authorized_call(sock, "caller", "triggered")
        access.assert_called_once_with("rejected", "caller", "shelly_failed")
        hangup.assert_called_once_with(sock)


class HealthcheckTests(unittest.TestCase):
    def test_healthcheck_accepts_fresh_ctrl_and_expected_shelly(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "health.json"
            path.write_text(
                json.dumps({"ctrl_connected": True, "updated_at": 100}),
                encoding="utf-8",
            )
            healthcheck.HEALTH_PATH = str(path)
            healthcheck.check_ctrl_state(now=110)
        with mock.patch.object(
            healthcheck.urllib.request,
            "urlopen",
            return_value=fake_response({"id": healthcheck.SHELLY_EXPECTED_ID}),
        ):
            healthcheck.check_shelly()

    def test_healthcheck_rejects_stale_ctrl_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "health.json"
            path.write_text(
                json.dumps({"ctrl_connected": True, "updated_at": 100}),
                encoding="utf-8",
            )
            healthcheck.HEALTH_PATH = str(path)
            with self.assertRaisesRegex(RuntimeError, "stale"):
                healthcheck.check_ctrl_state(now=200)

    def test_healthcheck_rejects_wrong_shelly(self):
        with mock.patch.object(
            healthcheck.urllib.request,
            "urlopen",
            return_value=fake_response({"id": "wrong-device"}),
        ):
            with self.assertRaisesRegex(RuntimeError, "wrong Shelly"):
                healthcheck.check_shelly()


class RegistrationWatchdogTests(unittest.TestCase):
    def test_registration_failures_are_counted_since_last_success(self):
        events = gatehook.parse_registration_events(
            [
                "REGISTER_OK 200 OK",
                "connection timed out [110]",
                "REGISTER_FAIL service unavailable",
            ]
        )
        self.assertEqual(["ok", "timeout", "fail"], events)
        self.assertEqual((False, 2), gatehook.analyze_registration(events))

    def test_registration_success_clears_prior_failures(self):
        self.assertEqual(
            (True, 0),
            gatehook.analyze_registration(["timeout", "fail", "ok"]),
        )


if __name__ == "__main__":
    unittest.main()
