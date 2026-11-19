"""Outbound incident routing to PagerDuty (Events API v2) and Slack (incoming webhook).

Both credentials are secrets resolved at send time and never stored in the database:

* PagerDuty integration (routing) key - secret name ``pagerduty_routing_key``
* Slack incoming-webhook URL (the URL is the credential) - secret name ``slack_webhook_url``

PagerDuty de-duplicates on ``dedup_key``, so re-sending a trigger for the same incident
adds to the existing alert instead of paging again. Slack has no de-duplication.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

import httpx

from oplia_ctl.http import HttpError, ResilientClient
from oplia_ctl.secrets import SecretProvider

log = logging.getLogger("oplia.aiops.notify")

Severity = Literal["critical", "error", "warning", "info"]
Phase = Literal["opened", "pre_action", "result", "predicted"]
ChannelName = Literal["pagerduty", "slack"]

PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
_PD_SUMMARY_MAX = 1024
_PD_DEDUP_MAX = 255
_SLACK_HEADER_MAX = 150
_SLACK_TEXT_MAX = 2900

_PHASE_TITLE: dict[str, str] = {
    "opened": "Incident detected",
    "pre_action": "Self-healing action starting",
    "result": "Self-healing action finished",
    "predicted": "Predicted risk",
}


class NotificationError(Exception):
    """A channel could not deliver a message."""


@dataclass(frozen=True)
class Incident:
    dedup_key: str
    summary: str
    severity: Severity
    source: str
    klass: str
    component: str | None = None
    group: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    links: tuple[tuple[str, str], ...] = ()  # (href, text)


class Channel(Protocol):
    name: ChannelName

    def send(self, incident: Incident, phase: Phase) -> bool:
        """Deliver; return False when the channel deliberately skips this phase. Raise on failure."""
        ...


class PagerDutyChannel:
    name: ChannelName = "pagerduty"

    def __init__(self, *, secrets: SecretProvider, client: ResilientClient, routing_key_secret: str,
                 events_url: str = PAGERDUTY_EVENTS_URL, clock: Any = None) -> None:
        if not events_url.startswith("https://"):
            raise ValueError("PagerDuty events URL must use https")
        self._secrets = secrets
        self._client = client
        self._key_secret = routing_key_secret
        self._url = events_url
        self._clock = clock or (lambda: datetime.now(UTC))

    def send(self, incident: Incident, phase: Phase) -> bool:
        if phase == "result":
            return False  # the alert stays open for a human to resolve after checking the outcome
        try:
            routing_key = self._secrets.get(self._key_secret)
        except LookupError as exc:
            raise NotificationError(f"PagerDuty routing key secret missing: {exc}") from None
        payload: dict[str, Any] = {
            "summary": f"[{_PHASE_TITLE[phase]}] {incident.summary}"[:_PD_SUMMARY_MAX],
            "source": incident.source[:255],
            "severity": incident.severity,
            "timestamp": self._clock().isoformat(),
            "class": incident.klass[:255],
            "custom_details": {"phase": phase, **incident.details},
        }
        if incident.component:
            payload["component"] = incident.component[:255]
        if incident.group:
            payload["group"] = incident.group[:255]
        body: dict[str, Any] = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": incident.dedup_key[:_PD_DEDUP_MAX],
            "client": "OPLIA Control Plane",
            "payload": payload,
        }
        if incident.links:
            body["links"] = [{"href": h, "text": t} for h, t in incident.links]
        try:
            self._client.request("POST", self._url, json=body, expected={202})
        except (HttpError, httpx.HTTPError) as exc:
            raise NotificationError(f"PagerDuty: {type(exc).__name__}: {str(exc)[:200]}") from None
        return True


def _mrkdwn_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class SlackChannel:
    name: ChannelName = "slack"

    def __init__(self, *, secrets: SecretProvider, client: ResilientClient, webhook_secret: str) -> None:
        self._secrets = secrets
        self._client = client
        self._secret = webhook_secret

    @staticmethod
    def build_message(incident: Incident, phase: Phase) -> dict[str, Any]:
        title = f"{_PHASE_TITLE[phase]}: {incident.summary}"
        lines = [f"*Severity:* {incident.severity}", f"*Source:* {_mrkdwn_escape(incident.source)}"]
        if incident.component:
            lines.append(f"*Component:* {_mrkdwn_escape(incident.component)}")
        for k, v in incident.details.items():
            lines.append(f"*{_mrkdwn_escape(str(k))}:* {_mrkdwn_escape(str(v))}")
        for href, text in incident.links:
            lines.append(f"<{href}|{_mrkdwn_escape(text)}>")
        body_text = "\n".join(lines)[:_SLACK_TEXT_MAX]
        return {
            "text": title[:_SLACK_TEXT_MAX],  # fallback for notifications and clients without blocks
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": title[:_SLACK_HEADER_MAX]}},
                {"type": "section", "text": {"type": "mrkdwn", "text": body_text}},
                {"type": "context", "elements": [
                    {"type": "mrkdwn", "text": f"OPLIA · dedup `{_mrkdwn_escape(incident.dedup_key[:80])}`"}]},
            ],
        }

    def send(self, incident: Incident, phase: Phase) -> bool:
        try:
            url = self._secrets.get(self._secret)
        except LookupError as exc:
            raise NotificationError(f"Slack webhook secret missing: {exc}") from None
        if not url.startswith("https://hooks.slack.com/"):
            raise NotificationError("Slack webhook URL must start with https://hooks.slack.com/")
        try:
            self._client.request("POST", url, json=self.build_message(incident, phase), expected={200})
        except (HttpError, httpx.HTTPError) as exc:
            # never echo the URL: it is the credential
            raise NotificationError(f"Slack: {type(exc).__name__}"
                                    f"{' status ' + str(exc.status) if isinstance(exc, HttpError) else ''}") from None
        return True


class IncidentNotifier:
    """Fans one message out to the configured channels and reports per-channel outcome."""

    def __init__(self, channels: list[Channel]) -> None:
        names = [c.name for c in channels]
        if len(names) != len(set(names)):
            raise ValueError("duplicate notification channel")
        self._channels = {c.name: c for c in channels}

    @property
    def channel_names(self) -> list[str]:
        return list(self._channels)

    def notify(self, incident: Incident, phase: Phase,
               only: list[str] | None = None) -> dict[str, str]:
        results: dict[str, str] = {}
        for name, ch in self._channels.items():
            if only is not None and name not in only:
                continue
            try:
                results[name] = "delivered" if ch.send(incident, phase) else "skipped"
            except NotificationError as exc:
                log.warning("notification via %s failed: %s", name, exc)
                results[name] = f"failed: {exc}"
        if only is not None:
            for wanted in only:
                results.setdefault(wanted, "failed: channel not configured")
        return results

    @staticmethod
    def any_delivered(results: dict[str, str]) -> bool:
        return any(v == "delivered" for v in results.values())
