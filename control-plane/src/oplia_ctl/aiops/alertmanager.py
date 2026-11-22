"""Prometheus Alertmanager webhook adapter.

Alertmanager cannot sign requests with HMAC, so ``POST /webhooks/aiops/alertmanager`` is
authenticated with a bearer token (Alertmanager ``http_config.authorization.credentials``),
compared in constant time with the secret ``alertmanager_webhook_token``.

Each *firing* alert is converted to an :class:`Alert` from these labels/annotations::

    labels:       cluster, namespace, oplia_workload_kind, oplia_workload_name,
                  oplia_hpa (optional), oplia_database (optional), oplia_metric
    annotations:  oplia_value: '{{ $value }}'
                  oplia_correlated: '{"db_active_connections_ratio": 0.95}'   (optional JSON)
                  summary (optional)

Resolved alerts are ignored. A malformed alert is reported in the response and does not
block the others (Alertmanager would otherwise retry the whole group forever).
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import ValidationError

from oplia_ctl.aiops.matrix import Alert

MAX_ALERTS_PER_REQUEST = 200


def to_alerts(payload: Any) -> list[tuple[str, Alert | None, str | None]]:
    """Return ``(fingerprint, alert, error)`` per firing alert."""
    if not isinstance(payload, dict) or not isinstance(payload.get("alerts"), list):
        raise ValueError("not an Alertmanager webhook payload (missing 'alerts' list)")
    alerts = payload["alerts"]
    if len(alerts) > MAX_ALERTS_PER_REQUEST:
        raise ValueError(f"more than {MAX_ALERTS_PER_REQUEST} alerts in one request")
    out: list[tuple[str, Alert | None, str | None]] = []
    for raw in alerts:
        if not isinstance(raw, dict) or raw.get("status") != "firing":
            continue
        labels = raw.get("labels") or {}
        ann = raw.get("annotations") or {}
        fp = str(raw.get("fingerprint") or "")[:64]
        if not re.fullmatch(r"[0-9a-f]{1,64}", fp):
            out.append((fp, None, "missing or invalid fingerprint"))
            continue
        try:
            correlated = json.loads(ann["oplia_correlated"]) if ann.get("oplia_correlated") else {}
            workload: dict[str, Any] = {
                "namespace": labels.get("namespace"),
                "kind": labels.get("oplia_workload_kind"),
                "name": labels.get("oplia_workload_name"),
            }
            if labels.get("oplia_hpa"):
                workload["hpa"] = labels["oplia_hpa"]
            if labels.get("oplia_database"):
                workload["database"] = labels["oplia_database"]
            alert = Alert.model_validate({
                "alert_id": f"am-{fp}",
                "source": "alertmanager",
                "cluster": labels.get("cluster"),
                "metric": labels.get("oplia_metric"),
                "value": float(ann.get("oplia_value", "nan")),
                "observed_at": raw.get("startsAt"),
                "correlated": correlated,
                "workload": workload,
                "summary": str(ann.get("summary", ""))[:500],
            })
            out.append((fp, alert, None))
        except (ValidationError, ValueError, TypeError) as exc:
            msg = (f"{len(exc.errors())} validation error(s): " +
                   "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:5])
                   if isinstance(exc, ValidationError) else f"{type(exc).__name__}: {exc}")
            out.append((fp, None, msg[:500]))
    return out
