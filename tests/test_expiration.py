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

    def test_gate_trigger_resets_relay_before_one_second_pulse(self):
        response = mock.MagicMock()
        response.status = 200
        response.read.return_value = b'{"was_on": false}'
        response.__enter__.return_value = response
        with mock.patch.object(
            gatehook.urllib.request, "urlopen", return_value=response
        ) as urlopen, mock.patch.object(gatehook.time, "sleep") as sleep:
            self.assertTrue(gatehook.trigger_shelly())

        self.assertEqual(2, urlopen.call_count)
        first_request = urlopen.call_args_list[0].args[0]
        second_request = urlopen.call_args_list[1].args[0]
        self.assertEqual({"id": 0, "on": False}, json.loads(first_request.data))
        self.assertEqual(
            {"id": 0, "on": True, "toggle_after": gatehook.SHELLY_PULSE_SECONDS},
            json.loads(second_request.data),
        )
        sleep.assert_called_once_with(gatehook.SHELLY_RESET_SECONDS)


if __name__ == "__main__":
    unittest.main()
