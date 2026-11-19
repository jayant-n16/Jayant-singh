"""HTTP API: signed webhooks in, human approvals and execution out.

Endpoints
---------
GET  /healthz                         liveness
GET  /readyz                          readiness (database reachable)
POST /webhooks/drift                  signed drift event -> drift.remediate proposal
POST /webhooks/runtime-threat         signed Falco event -> SIEM export (+ isolation proposal)
GET  /proposals                       list (operator/approver)
GET  /proposals/{id}                  detail (operator/approver)
POST /proposals/{id}/approve          approver
POST /proposals/{id}/reject           approver
POST /proposals/{id}/execute          operator (runs the registered executor through the gate)
POST /webhooks/aiops/alert            signed RCA alert -> matrix -> self-healing proposal + PagerDuty/Slack
POST /webhooks/aiops/alertmanager     Alertmanager webhook (bearer token) -> same engine, one result per alert
POST /webhooks/aiops/prediction       signed predictive risk -> escalation schedule
GET  /aiops/predictions               list scheduled/escalated predictions (operator/approver)
POST /aiops/predictions/{id}/cancel   operator/approver: withdraw a scheduled prediction
POST /kill-switch                     approver: engage/release
GET  /audit/verify                    approver: verify the audit hash chain
"""


import hmac
import json
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import text

from oplia_ctl.aiops.alertmanager import to_alerts
from oplia_ctl.aiops.engine import AIOpsEngine, AlertRejectedError
from oplia_ctl.aiops.escalation import EscalationScheduler, Prediction, PredictionOutOfWindowError
from oplia_ctl.aiops.matrix import Alert
from oplia_ctl.aiops.models import PredictionStatus
from oplia_ctl.auth import AuthError, OIDCVerifier, Principal, verify_webhook
from oplia_ctl.remediation.drift import BlueprintNotAllowedError, DriftEvent, propose_drift_remediation
from oplia_ctl.safety import (
    Executor,
    ExpiredError,
    FourEyesViolationError,
    InvalidTransitionError,
    KillSwitchEngagedError,
    NotApprovedError,
    NotFoundError,
    Proposal,
    ProposalStatus,
    SafetyGate,
)
from oplia_ctl.secrets import SecretNotFoundError, SecretProvider
from oplia_ctl.soar.exporter import SOARExporter

MAX_WEBHOOK_BYTES = 256 * 1024


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str = Field(default="", max_length=2000)


class KillSwitchBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    engaged: bool
    reason: str = Field(min_length=3, max_length=2000)


def _proposal_json(p: Proposal) -> dict[str, Any]:
    return {
        "id": p.id,
        "action_type": p.action_type,
        "target": p.target,
        "payload": p.payload,
        "reason": p.reason,
        "requested_by": p.requested_by,
        "status": p.status.value,
        "created_at": p.created_at.isoformat(),
        "expires_at": p.expires_at.isoformat(),
        "decided_by": p.decided_by,
        "decided_at": p.decided_at.isoformat() if p.decided_at else None,
        "decision_note": p.decision_note,
        "executed_at": p.executed_at.isoformat() if p.executed_at else None,
        "result": p.result,
    }


def create_app(
    *,
    gate: SafetyGate,
    secrets: SecretProvider,
    verifier: OIDCVerifier,
    executors: dict[str, Executor],
    webhook_secret_name: str,
    webhook_max_skew_seconds: int,
    allowed_blueprints: list[str],
    approver_role: str,
    operator_role: str,
    soar_exporter: SOARExporter | None = None,
    aiops_engine: AIOpsEngine | None = None,
    escalation: EscalationScheduler | None = None,
    alertmanager_token_secret: str = "alertmanager_webhook_token",  # noqa: S107 - a secret NAME
    db_ping: Callable[[], None] | None = None,
) -> FastAPI:
    app = FastAPI(title="OPLIA Control Plane", version="0.1.0", docs_url=None, redoc_url=None)

    # ------------------------------------------------------------ auth deps
    def principal(authorization: Annotated[str | None, Header()] = None) -> Principal:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bearer token required",
                                headers={"WWW-Authenticate": "Bearer"})
        try:
            return verifier.verify(authorization.split(" ", 1)[1].strip())
        except AuthError as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc),
                                headers={"WWW-Authenticate": "Bearer"}) from None

    def require(*roles: str) -> Callable[[Principal], Principal]:
        def dep(p: Annotated[Principal, Depends(principal)]) -> Principal:
            if not any(p.has_role(r) for r in roles):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
            return p
        return dep

    approver = require(approver_role)
    reader = require(approver_role, operator_role)
    operator = require(operator_role)

    async def signed_body(
        request: Request,
        x_oplia_timestamp: Annotated[str | None, Header()] = None,
        x_oplia_signature: Annotated[str | None, Header()] = None,
    ) -> bytes:
        body = await request.body()
        if len(body) > MAX_WEBHOOK_BYTES:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "payload too large")
        try:
            secret = secrets.get(webhook_secret_name)
        except SecretNotFoundError:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "webhook secret not configured") from None
        try:
            verify_webhook(secret=secret, timestamp=x_oplia_timestamp, signature=x_oplia_signature,
                           body=body, max_skew_seconds=webhook_max_skew_seconds)
        except AuthError as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from None
        return body

    def _json(body: bytes) -> Any:
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "body is not valid JSON") from None

    def _gate_call(fn: Callable[[], Proposal]) -> dict[str, Any]:
        try:
            return _proposal_json(fn())
        except NotFoundError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "proposal not found") from None
        except (InvalidTransitionError, NotApprovedError, ExpiredError) as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, f"{type(exc).__name__}: {exc}") from None
        except FourEyesViolationError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from None
        except KillSwitchEngagedError as exc:
            raise HTTPException(status.HTTP_423_LOCKED, str(exc)) from None

    # --------------------------------------------------------------- health
    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> dict[str, str]:
        if db_ping is not None:
            try:
                db_ping()
            except Exception:
                raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "database unavailable") from None
        return {"status": "ready"}

    # ------------------------------------------------------------- webhooks
    @app.post("/webhooks/drift", status_code=status.HTTP_202_ACCEPTED)
    def drift_webhook(
        body: Annotated[bytes, Depends(signed_body)],
        x_oplia_delivery: Annotated[str | None, Header()] = None,
    ) -> dict[str, Any]:
        if not x_oplia_delivery or len(x_oplia_delivery) > 64:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "X-OPLIA-Delivery header (<=64 chars) required")
        try:
            event = DriftEvent.model_validate(_json(body))
            proposal = propose_drift_remediation(gate, event, delivery_id=x_oplia_delivery,
                                                 allowed_blueprints=allowed_blueprints)
        except ValidationError as exc:
            raise HTTPException(422,
                                json.loads(exc.json(include_url=False, include_input=False))) from None
        except BlueprintNotAllowedError as exc:
            raise HTTPException(422, str(exc)) from None
        return _proposal_json(proposal)

    @app.post("/webhooks/runtime-threat", status_code=status.HTTP_202_ACCEPTED)
    def runtime_threat_webhook(body: Annotated[bytes, Depends(signed_body)]) -> dict[str, Any]:
        if soar_exporter is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "SOAR exporter not configured")
        raw = _json(body)
        if not isinstance(raw, dict):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "event must be a JSON object")
        return soar_exporter.process(raw)

    def _validation_422(exc: ValidationError) -> HTTPException:
        return HTTPException(422, json.loads(exc.json(include_url=False, include_input=False)))

    @app.post("/webhooks/aiops/alert", status_code=status.HTTP_202_ACCEPTED)
    def aiops_alert(body: Annotated[bytes, Depends(signed_body)]) -> dict[str, Any]:
        if aiops_engine is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "AIOps engine not configured")
        try:
            alert = Alert.model_validate(_json(body))
        except ValidationError as exc:
            raise _validation_422(exc) from None
        try:
            return aiops_engine.handle(alert)
        except AlertRejectedError as exc:
            raise HTTPException(422, str(exc)) from None

    async def alertmanager_body(request: Request,
                                authorization: Annotated[str | None, Header()] = None) -> bytes:
        try:
            expected = secrets.get(alertmanager_token_secret)
        except SecretNotFoundError:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "alertmanager token not configured") from None
        given = authorization[7:].strip() if authorization and authorization.lower().startswith("bearer ") else ""
        if not given or not hmac.compare_digest(given.encode(), expected.encode()):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid bearer token",
                                headers={"WWW-Authenticate": "Bearer"})
        body = await request.body()
        if len(body) > MAX_WEBHOOK_BYTES:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "payload too large")
        return body

    @app.post("/webhooks/aiops/alertmanager")
    def aiops_alertmanager(body: Annotated[bytes, Depends(alertmanager_body)]) -> dict[str, Any]:
        if aiops_engine is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "AIOps engine not configured")
        try:
            converted = to_alerts(_json(body))
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
        results: list[dict[str, Any]] = []
        for fp, alert, error in converted:
            if alert is None:
                results.append({"fingerprint": fp, "outcome": "invalid", "error": error})
                continue
            try:
                results.append({"fingerprint": fp, **aiops_engine.handle(alert)})
            except AlertRejectedError as exc:
                results.append({"fingerprint": fp, "outcome": "rejected", "error": str(exc)})
        return {"results": results}

    @app.post("/webhooks/aiops/prediction", status_code=status.HTTP_202_ACCEPTED)
    def aiops_prediction(body: Annotated[bytes, Depends(signed_body)]) -> dict[str, Any]:
        if escalation is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "escalation scheduler not configured")
        try:
            prediction = Prediction.model_validate(_json(body))
        except ValidationError as exc:
            raise _validation_422(exc) from None
        try:
            return escalation.submit(prediction)
        except PredictionOutOfWindowError as exc:
            raise HTTPException(422, str(exc)) from None

    @app.get("/aiops/predictions")
    def list_predictions(
        _: Annotated[Principal, Depends(reader)],
        status_filter: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if escalation is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "escalation scheduler not configured")
        st = None
        if status_filter is not None:
            try:
                st = PredictionStatus(status_filter)
            except ValueError:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "unknown status") from None
        return escalation.list(st, limit)

    @app.post("/aiops/predictions/{prediction_id}/cancel")
    def cancel_prediction(prediction_id: str, body: DecisionBody,
                          p: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        if escalation is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "escalation scheduler not configured")
        try:
            return escalation.cancel(prediction_id, p.subject, body.note)
        except LookupError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "prediction not found") from None
        except ValueError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None

    # ------------------------------------------------------------ proposals
    @app.get("/proposals")
    def list_proposals(
        _: Annotated[Principal, Depends(reader)],
        status_filter: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        st = None
        if status_filter is not None:
            try:
                st = ProposalStatus(status_filter)
            except ValueError:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "unknown status") from None
        return [_proposal_json(p) for p in gate.list(st, max(1, min(limit, 500)))]

    @app.get("/proposals/{proposal_id}")
    def get_proposal(proposal_id: str, _: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        return _gate_call(lambda: gate.get(proposal_id))

    @app.post("/proposals/{proposal_id}/approve")
    def approve(proposal_id: str, body: DecisionBody,
                p: Annotated[Principal, Depends(approver)]) -> dict[str, Any]:
        return _gate_call(lambda: gate.approve(proposal_id, p.subject, body.note))

    @app.post("/proposals/{proposal_id}/reject")
    def reject(proposal_id: str, body: DecisionBody,
               p: Annotated[Principal, Depends(approver)]) -> dict[str, Any]:
        return _gate_call(lambda: gate.reject(proposal_id, p.subject, body.note))

    @app.post("/proposals/{proposal_id}/execute")
    def execute(proposal_id: str, p: Annotated[Principal, Depends(operator)]) -> dict[str, Any]:
        current = _gate_call(lambda: gate.get(proposal_id))
        executor = executors.get(current["action_type"])
        if executor is None:
            raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED,
                                f"no executor registered for {current['action_type']}")
        return _gate_call(lambda: gate.execute(proposal_id, executor, p.subject))

    # ---------------------------------------------------------- governance
    @app.post("/kill-switch")
    def kill_switch(body: KillSwitchBody, p: Annotated[Principal, Depends(approver)]) -> dict[str, Any]:
        gate.set_kill_switch(engaged=body.engaged, actor=p.subject, reason=body.reason)
        return {"engaged": gate.kill_switch_engaged()}

    @app.get("/audit/verify")
    def audit_verify(_: Annotated[Principal, Depends(approver)]) -> dict[str, bool]:
        return {"intact": gate.verify_audit_chain()}

    return app


def sqlalchemy_ping(engine: Any) -> Callable[[], None]:
    def ping() -> None:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    return ping
