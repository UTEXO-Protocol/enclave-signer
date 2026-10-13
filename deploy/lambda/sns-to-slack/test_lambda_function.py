"""Offline regression checks: python3 -m unittest discover -s deploy/lambda/sns-to-slack."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch


# Import without creating an AWS client or looking up credentials.
_spec = importlib.util.spec_from_file_location(
    "slack_relay", Path(__file__).with_name("lambda_function.py")
)
relay = importlib.util.module_from_spec(_spec)
with patch.dict("sys.modules", {"boto3": Mock()}):
    _spec.loader.exec_module(relay)


class FormattingTests(unittest.TestCase):
    def test_normal_alarm_keeps_relay_formatting(self):
        alarm = {
            "AlarmName": "Enclave health",
            "NewStateValue": "ALARM",
            "NewStateReason": "Threshold crossed",
            "Trigger": {"Dimensions": [{"name": "CID", "value": "16"}]},
            "Region": "eu-central-1",
        }
        self.assertEqual(
            relay._format({"Message": json.dumps(alarm)}),
            ":red_circle: *Enclave health* → *ALARM*\n"
            "Threshold crossed\n`CID=16`  ·  eu-central-1",
        )

    def test_all_alarm_fields_escape_slack_control_sequences(self):
        raw = "<!channel> <!here> <@U0123> <https://evil.example|Open runbook> &"
        escaped = (
            "&lt;!channel&gt; &lt;!here&gt; &lt;@U0123&gt; "
            "&lt;https://evil.example|Open runbook&gt; &amp;"
        )
        alarm = {
            "AlarmName": raw,
            "NewStateValue": raw,
            "NewStateReason": raw,
            "Trigger": {"Dimensions": [{"name": raw, "value": raw}]},
            "Region": raw,
        }
        self.assertEqual(
            relay._format({"Message": json.dumps(alarm)}),
            f":grey_question: *{escaped}* → *{escaped}*\n"
            f"{escaped}\n`{escaped}={escaped}`  ·  {escaped}",
        )

    def test_fallback_escapes_subject_and_raw_message(self):
        for message, expected in [
            ("<@U0123> & goodbye", "&lt;@U0123&gt; &amp; goodbye"),
            ('{"text":"<!channel>"}', '{"text":"&lt;!channel&gt;"}'),
            ('["<!here>"]', '["&lt;!here&gt;"]'),
        ]:
            with self.subTest(message=message):
                self.assertEqual(
                    relay._format({"Subject": "<!channel>", "Message": message}),
                    f"*&lt;!channel&gt;*\n{expected}",
                )

    def test_escape_only_slack_control_characters(self):
        self.assertEqual(
            relay._esc('&lt; *bold* `code` "quotes" < >'),
            '&amp;lt; *bold* `code` "quotes" &lt; &gt;',
        )
        self.assertEqual(relay._esc(16), "16")

    def test_handler_posts_escaped_payload_without_network(self):
        with patch.object(relay, "_webhook", return_value="https://example.invalid"), \
                patch.object(relay.urllib.request, "urlopen") as post:
            self.assertEqual(
                relay.handler({"Records": [{"Sns": {"Message": "<!here>"}}]}, None),
                {"ok": True},
            )
        post.assert_called_once()
        request = post.call_args.args[0]
        self.assertEqual(
            json.loads(request.data),
            {"text": "*CloudWatch notification*\n&lt;!here&gt;"},
        )


if __name__ == "__main__":
    unittest.main()
