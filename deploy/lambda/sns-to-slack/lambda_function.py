"""SNS -> Slack relay for enclave-host alerts (TODO §7a Track 2).

Subscribed to the SNS topic `utexo-stage-enclave-alerts`; CloudWatch alarms
publish here. Formats CloudWatch alarm notifications into a compact Slack
message and POSTs to a Slack incoming webhook.

The webhook URL is a SECRET and is NOT baked in: it is read at runtime from an
SSM SecureString whose name is passed via the `SLACK_WEBHOOK_SSM_PARAM` env var
(the Lambda role has `ssm:GetParameter` + `kms:Decrypt` on it only).
"""
import json
import os
import urllib.request

import boto3

_ssm = boto3.client("ssm")
_webhook_cache = None

_EMOJI = {
    "ALARM": ":red_circle:",
    "OK": ":large_green_circle:",
    "INSUFFICIENT_DATA": ":white_circle:",
}


def _webhook():
    global _webhook_cache
    if _webhook_cache is None:
        name = os.environ["SLACK_WEBHOOK_SSM_PARAM"]
        _webhook_cache = _ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    return _webhook_cache


def _format(sns) -> str:
    subject = sns.get("Subject") or "CloudWatch notification"
    message = sns.get("Message", "")
    try:
        alarm = json.loads(message)
    except (ValueError, TypeError):
        alarm = None

    if isinstance(alarm, dict) and "AlarmName" in alarm:
        state = alarm.get("NewStateValue", "?")
        emoji = _EMOJI.get(state, ":grey_question:")
        dims = ""
        try:
            dd = alarm.get("Trigger", {}).get("Dimensions", [])
            dims = "  ".join(f"`{d['name']}={d['value']}`" for d in dd)
        except (KeyError, TypeError):
            pass
        return (
            f"{emoji} *{alarm.get('AlarmName')}* → *{state}*\n"
            f"{alarm.get('NewStateReason', '')}\n"
            f"{dims}  ·  {alarm.get('Region', '')}"
        )
    return f"*{subject}*\n{message}"


def handler(event, _context):
    url = _webhook()
    for record in event.get("Records", []):
        text = _format(record.get("Sns", {}))
        payload = json.dumps({"text": text}).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    return {"ok": True}
