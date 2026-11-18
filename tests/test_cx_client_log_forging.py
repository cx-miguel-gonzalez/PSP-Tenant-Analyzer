"""Regression tests: user-controlled request paths must not forge log lines
(CWE-117) when cx_client._request logs a failed API call."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import cx_client  # noqa: E402


def _failing_response(status=400, text="bad request"):
    resp = mock.Mock()
    resp.ok = False
    resp.status_code = status
    resp.text = text
    return resp


class RequestLogForgingTest(unittest.TestCase):
    def _call(self, path):
        with mock.patch.object(cx_client, "_HTTP") as http:
            http.request.return_value = _failing_response()
            with self.assertLogs(cx_client.logger, level="WARNING") as captured:
                with self.assertRaises(cx_client.CxApiError):
                    cx_client.delete_preset(
                        "https://ast.checkmarx.net", "token", path
                    )
        return captured.records

    def test_crlf_in_preset_id_is_neutralised(self):
        forged = "1\r\nWARNING:cx_client:DELETE /admin failed (200): forged"
        records = self._call(forged)
        self.assertEqual(len(records), 1)
        message = records[0].getMessage()
        self.assertNotIn("\r", message)
        self.assertNotIn("\n", message)
        # The value is still logged, just encoded.
        self.assertIn("1\\r\\nWARNING:cx_client:DELETE /admin", message)

    def test_normal_preset_id_logged_unchanged(self):
        records = self._call("42")
        message = records[0].getMessage()
        self.assertIn(
            "DELETE /api/preset-manager/sast/presets/42 failed (400): bad request",
            message,
        )


if __name__ == "__main__":
    unittest.main()
