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
GET  /finops/findings                 tag-compliance log (operator/approver; ?status=OPEN&cloud=aws)
GET  /finops/scans                    recent compliance scans (operator/approver)
GET  /finops/candidates               idle resources tracked for clean-up (operator/approver)
GET  /jit/roles                       JIT role catalog (operator/approver)
POST /jit/requests                    operator/approver: request time-bound elevated access
GET  /jit/requests[/{id}]             operator/approver
POST /jit/requests/{id}/approve       approver (not the requester): approve and grant now
POST /jit/requests/{id}/reject        approver
POST /jit/requests/{id}/grant         approver: retry the grant of an approved request
POST /jit/requests/{id}/revoke        approver or the requester: revoke before expiry
GET  /dr/breakers                     DR circuit breaker state (operator/approver)
GET  /dr/incidents                    DR incidents with findings and actions (operator/approver)
POST /dr/breakers/{stream}/trip       approver: open the breaker manually (sever + alert + lock)
POST /dr/breakers/{stream}/reset      approver: close it; release or discard the held bundle; unlock
GET  /me                              any signed-in user: subject, roles, what the console may offer
GET  /kill-switch                     operator/approver: current state, who set it and why
POST /kill-switch                     approver: engage/release
GET  /audit/events                    approver: audit log, newest first (?before_seq=&limit=&proposal_id=)
GET  /audit/verify                    approver: verify the audit hash chain
GET  /inventory/instances             operator/approver: cached compute inventory (?cloud=&region=&state=)
GET  /inventory/scans                 operator/approver: inventory scan history
POST /inventory/instances/{id}/power  operator/approver: propose start/stop (compute.power, gated)
GET  /databases                       operator/approver: configured databases with their last health check
POST /databases/{name}/check          operator/approver: run a read-only health check now (audited)
GET  /databases/consistency           operator/approver: DR consistency runs (?pair=)
POST /databases/{name}/consistency    operator/approver: compare a DR copy with its source now (audited)
GET  /integrations                    operator/approver: status of clouds, CI/CD, IdPs, alerting, Vault (no secrets)
POST /integrations/{name}/test        approver: send a test notification (Slack, PagerDuty, SIEM; audited)
GET  /settings/integrations           approver: editable non-secret settings, their source, secret names + presence
POST /settings/integrations/{name}    approver: propose a settings change (secrets staged in Vault only; gated)
GET  /network/status                  operator/approver: Global Accelerator, Direct Connect, Consul, Linkerd
POST /network/endpoint-groups/{key}/traffic-dial   operator/approver: propose a traffic-dial change (gated)
GET  /dr/replication                  operator/approver: CDC pipelines, object pairs, image jobs
POST /dr/replication/pipelines/{name}/{action}     propose pause/resume/restart of a CDC connector (gated)
POST /dr/replication/objects/{pair}/plan           propose an incremental object sync (gated)
POST /dr/replication/objects/{pair}/deletions      propose removing target copies deleted at the source
                                                   (only pairs with replicate_deletions: true; gated)
POST /dr/replication/images                        propose a VM image replication (gated, worker runs it)
POST /dr/replication/tags/preview                  how tags map to aws/azure/gcp (no side effects)
GET  /dr/jobs                                       operator/approver: DR job modules (drills, ...) and their jobs
GET  /dr/jobs/{kind}/{id}                           operator/approver: one DR job with its persisted state
POST /dr/jobs/{kind}                               propose a DR job (gated; oplia-dr-job-worker runs it)
"""


import hmac
import json
import uuid
from collections.abc import Callable
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from oplia_ctl.aiops.alertmanager import to_alerts
from oplia_ctl.aiops.engine import AIOpsEngine, AlertRejectedError
from oplia_ctl.aiops.escalation import EscalationScheduler, Prediction, PredictionOutOfWindowError
from oplia_ctl.aiops.matrix import Alert
from oplia_ctl.aiops.models import PredictionStatus
from oplia_ctl.auth import AuthError, OIDCVerifier, Principal, verify_webhook
from oplia_ctl.cloud.power import parse_target as parse_power_target
from oplia_ctl.databases.consistency import ConsistencyChecker
from oplia_ctl.databases.registry import DatabaseRegistry
from oplia_ctl.dr.breaker import CircuitBreaker, list_incidents
from oplia_ctl.finops.compliance import list_findings, list_scans
from oplia_ctl.finops.optimizer import MaintenanceWindowClosedError, list_candidates
from oplia_ctl.identity.jit import JitConflictError, JitRequestError, JitService
from oplia_ctl.integration_settings import (
    ACTION_INTEGRATION_SETTINGS,
    MAX_BODY_BYTES,
    IntegrationSettingsService,
    SettingsError,
    new_change_id,
)
from oplia_ctl.integrations import IntegrationRegistry
from oplia_ctl.inventory.scanner import list_instances as list_inventory_instances
from oplia_ctl.inventory.scanner import list_scans as list_inventory_scans
from oplia_ctl.network.service import NetworkService
from oplia_ctl.remediation.drift import BlueprintNotAllowedError, DriftEvent, propose_drift_remediation
from oplia_ctl.replication.config import ACTION_PIPELINE
from oplia_ctl.replication.images import ACTION_IMAGE_REPLICATE, ImageReplicator, validate_request
from oplia_ctl.replication.jobs import JobMachine
from oplia_ctl.replication.objects import ACTION_OBJECT_DELETE, ACTION_OBJECT_SYNC, ObjectReplicator
from oplia_ctl.replication.pipelines import ACTIONS as PIPELINE_ACTIONS
from oplia_ctl.replication.pipelines import KafkaConnect
from oplia_ctl.replication.tags import map_tags
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


class JitRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: str = Field(min_length=1, max_length=128)
    requested_role: str = Field(min_length=1, max_length=64)
    target_cloud_account: str = Field(min_length=1, max_length=128)
    expiration_minutes: int = Field(ge=1, le=1440)
    justification: str = Field(min_length=10, max_length=1000)


class DrTripBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=5, max_length=2000)


class DrResetBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["release", "discard"]
    unlock_targets: bool = False
    note: str = Field(min_length=5, max_length=2000)


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str = Field(default="", max_length=2000)

ACTION_COMPUTE_POWER = "compute.power"
ACTION_TRAFFIC_DIAL = "network.traffic_dial"


class ImageReplicateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_cloud: Literal["aws", "azure", "gcp"]
    source_id: str = Field(min_length=3, max_length=512)
    target_cloud: Literal["aws", "azure", "gcp"]
    name: str = Field(min_length=2, max_length=63)
    reason: str = Field(min_length=5, max_length=2000)


class ReasonBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=5, max_length=2000)


class DrJobBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    params: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=5, max_length=2000)


class TagPreviewBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tags: dict[str, str] = Field(max_length=500)
    target: Literal["aws", "azure", "gcp"]


class TrafficDialBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    percentage: float = Field(ge=0, le=100)
    reason: str = Field(min_length=5, max_length=2000)


class PowerBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: Literal["start", "stop"]
    reason: str = Field(min_length=5, max_length=2000)


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
    finops_sf: sessionmaker[Session] | None = None,
    jit: JitService | None = None,
    dr_breaker: CircuitBreaker | None = None,
    db_ping: Callable[[], None] | None = None,
    inventory_sf: sessionmaker[Session] | None = None,
    db_registry: DatabaseRegistry | None = None,
    consistency: ConsistencyChecker | None = None,
    integrations: IntegrationRegistry | None = None,
    integration_settings: IntegrationSettingsService | None = None,
    network: NetworkService | None = None,
    kafka_connect: KafkaConnect | None = None,
    object_replicator: ObjectReplicator | None = None,
    image_replicator: ImageReplicator | None = None,
    dr_jobs: dict[str, JobMachine] | None = None,
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
        ready = getattr(executor, "check_ready", None)
        if ready is not None:
            try:
                ready(current["payload"])
            except MaintenanceWindowClosedError as exc:
                raise HTTPException(status.HTTP_409_CONFLICT, f"not executed: {exc}") from None
            except ValueError as exc:
                raise HTTPException(422, f"invalid payload: {exc}") from None
        return _gate_call(lambda: gate.execute(proposal_id, executor, p.subject))

    # --------------------------------------------------------------- finops
    def _finops() -> sessionmaker[Session]:
        if finops_sf is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "FinOps store not configured")
        return finops_sf

    @app.get("/finops/findings")
    def finops_findings(_: Annotated[Principal, Depends(reader)], status_filter: str | None = None,
                        cloud: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if status_filter not in (None, "OPEN", "RESOLVED"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "status_filter must be OPEN or RESOLVED")
        if cloud not in (None, "aws", "azure", "gcp", "ibm"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "cloud must be aws, azure, gcp or ibm")
        return list_findings(_finops(), status=status_filter, cloud=cloud, limit=limit)

    @app.get("/finops/scans")
    def finops_scans(_: Annotated[Principal, Depends(reader)], limit: int = 20) -> list[dict[str, Any]]:
        return list_scans(_finops(), limit)

    @app.get("/finops/candidates")
    def finops_candidates(_: Annotated[Principal, Depends(reader)], limit: int = 200) -> list[dict[str, Any]]:
        return list_candidates(_finops(), limit)

    # ------------------------------------------------------------ inventory
    def _inventory() -> sessionmaker[Session]:
        if inventory_sf is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "compute inventory not configured (no cloud)")
        return inventory_sf

    @app.get("/inventory/instances")
    def inventory_instances(_: Annotated[Principal, Depends(reader)], cloud: str | None = None,
                            region: str | None = None, state: str | None = None, include_gone: bool = False,
                            limit: int = 500) -> list[dict[str, Any]]:
        if cloud not in (None, "aws", "azure", "gcp", "ibm"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "cloud must be aws, azure, gcp or ibm")
        return list_inventory_instances(_inventory(), cloud=cloud, region=region or None, state=state or None,
                                        include_gone=include_gone, limit=limit)

    @app.post("/inventory/instances/{instance_id}/power", status_code=status.HTTP_201_CREATED)
    def inventory_power(instance_id: str, body: PowerBody,
                        p: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        rows = [r for r in list_inventory_instances(_inventory(), include_gone=False, limit=2000)
                if r["id"] == instance_id]
        if not rows:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "instance not in the current inventory")
        inst = rows[0]
        try:
            parse_power_target(inst["cloud"], inst["resource_id"])
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None
        proposal = gate.propose(
            action_type=ACTION_COMPUTE_POWER, target=inst["resource_id"],
            payload={"cloud": inst["cloud"], "resource_id": inst["resource_id"], "operation": body.operation,
                     "name": inst["name"]},
            reason=f"{body.operation} {inst['cloud']} instance {inst['name']}: {body.reason}"[:2000],
            requested_by=p.subject)
        return _proposal_json(proposal)

    @app.get("/inventory/scans")
    def inventory_scans(_: Annotated[Principal, Depends(reader)], limit: int = 20) -> list[dict[str, Any]]:
        return list_inventory_scans(_inventory(), limit)

    # ------------------------------------------------------------ databases
    def _dbs() -> DatabaseRegistry:
        if db_registry is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "no databases configured (OPLIA_DATABASES)")
        return db_registry

    @app.get("/databases")
    def databases(_: Annotated[Principal, Depends(reader)]) -> list[dict[str, Any]]:
        return _dbs().latest()

    @app.post("/databases/{name}/check")
    def database_check(name: str, p: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        reg = _dbs()
        if name not in reg.specs:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown database")
        result = reg.check(name, triggered_by=p.subject)
        gate.record_event(actor=p.subject, event="db_health_check",
                          detail={"database": name, "ok": result["ok"], "latency_ms": result["latency_ms"]})
        return result

    def _consistency() -> ConsistencyChecker:
        if consistency is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "no DR database pairs configured")
        return consistency

    @app.get("/databases/consistency")
    def consistency_runs(_: Annotated[Principal, Depends(reader)], pair: str | None = None,
                         limit: int = 50) -> list[dict[str, Any]]:
        return _consistency().list_runs(pair=pair, limit=limit)

    @app.post("/databases/{name}/consistency")
    def consistency_run(name: str, p: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        checker = _consistency()
        if name not in [dst.name for _src, dst in checker.pairs()]:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not a configured DR copy (needs dr_of)")
        return checker.run(name, triggered_by=p.subject)

    # ---------------------------------------------------------- integrations
    def _integrations() -> IntegrationRegistry:
        if integrations is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "integration status not available")
        return integrations

    @app.get("/integrations")
    def integrations_status(_: Annotated[Principal, Depends(reader)]) -> list[dict[str, Any]]:
        return _integrations().status()

    @app.post("/integrations/{name}/test")
    def integrations_test(name: str, p: Annotated[Principal, Depends(approver)]) -> dict[str, Any]:
        reg = _integrations()
        try:
            detail = reg.send_test(name, p.subject)
            ok, error = True, None
        except LookupError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown integration") from None
        except ValueError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
        except Exception as exc:  # the failure is the answer: report and audit it
            ok, detail, error = False, "", f"{type(exc).__name__}: {str(exc)[:300]}"
        gate.record_event(actor=p.subject, event="integration_test_notification",
                          detail={"integration": name, "ok": ok, "error": error})
        return {"integration": name, "ok": ok, "detail": detail, "error": error}

    # ------------------------------------------------------ integration settings
    def _settings_svc() -> IntegrationSettingsService:
        if integration_settings is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "integration settings not available")
        return integration_settings

    @app.get("/settings/integrations")
    def settings_list(_: Annotated[Principal, Depends(approver)]) -> dict[str, Any]:
        return _settings_svc().describe_all()

    @app.post("/settings/integrations/{name}")
    async def settings_propose(name: str, request: Request,
                               p: Annotated[Principal, Depends(approver)]) -> dict[str, Any]:
        svc = _settings_svc()
        raw = await request.body()  # parsed here, not by FastAPI, so a validation error can never echo a secret
        if len(raw) > MAX_BODY_BYTES:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "request too large")
        try:
            body = json.loads(raw or b"null")
        except json.JSONDecodeError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "body is not valid JSON") from None
        try:
            change = svc.parse(name, body)
        except LookupError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown integration") from None
        except SettingsError as exc:
            raise HTTPException(422, str(exc)) from None
        finally:
            body = None
        svc.purge_stale_staging()
        change_id = new_change_id()
        proposal = gate.propose(action_type=ACTION_INTEGRATION_SETTINGS, target=f"integration {name}",
                                payload=svc.payload(change, change_id, p.subject),
                                reason=f"Integration settings ({name}): {change.reason}", requested_by=p.subject)
        if change.secrets:
            try:
                svc.stage_secrets(change_id, change.secrets)
            except Exception as exc:
                change.secrets.clear()
                try:
                    svc.destroy_staging(change_id)
                finally:
                    gate.reject(proposal.id, "oplia-settings",
                                f"secret staging in Vault failed ({type(exc).__name__}); nothing was changed")
                detail = str(getattr(exc, "status", "")) or type(exc).__name__
                raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                                    f"could not stage the secret(s) in Vault ({detail}); "
                                    "the proposal was rejected and nothing was changed") from None
            gate.record_event(actor=p.subject, event="settings_secrets_staged", proposal_id=proposal.id,
                              detail={"integration": name, "secret_names": sorted(change.secrets)})
            change.secrets.clear()
        return _proposal_json(gate.get(proposal.id))

    # -------------------------------------------------------------- network
    def _network() -> NetworkService:
        if network is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "network layer not configured (OPLIA_NETWORK_*)")
        return network

    @app.get("/network/status")
    def network_status(_: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        return _network().status()

    @app.post("/network/endpoint-groups/{key}/traffic-dial", status_code=status.HTTP_201_CREATED)
    def network_traffic_dial(key: str, body: TrafficDialBody,
                             p: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        net = _network()
        if key not in net.cfg.endpoint_groups:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown endpoint group")
        try:
            live = net.endpoint_group(key)
        except Exception as exc:  # cannot propose a step without knowing the current dial
            raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                                f"could not read endpoint group: {type(exc).__name__}: {str(exc)[:300]}") from None
        try:
            net.check_step(key, live["traffic_dial"], body.percentage, live["all_healthy"])
        except ValueError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
        proposal = gate.propose(
            action_type=ACTION_TRAFFIC_DIAL, target=live["arn"],
            payload={"group": key, "arn": live["arn"], "from": live["traffic_dial"], "to": body.percentage,
                     "request_id": str(uuid.uuid4())},
            reason=f"traffic dial {key} {live['traffic_dial']:g} % -> {body.percentage:g} %: {body.reason}"[:2000],
            requested_by=p.subject)
        return _proposal_json(proposal)

    # ---------------------------------------------------------- replication
    replication_on = kafka_connect is not None or object_replicator is not None or image_replicator is not None

    @app.get("/dr/replication")
    def replication_status(_: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        if not replication_on:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "replication not configured (OPLIA_REPLICATION_*)")
        pipes: dict[str, Any] = {"configured": kafka_connect is not None, "ok": True, "items": [],
                                 "error": None}
        if kafka_connect is not None:
            try:
                pipes["items"] = kafka_connect.connectors()
            except Exception as exc:  # reported, never hides the other sections
                pipes.update(ok=False, error=f"{type(exc).__name__}: {str(exc)[:300]}")
        img_cfg = image_replicator.cfg if image_replicator else None
        return {"pipelines": pipes,
                "object_pairs": object_replicator.status() if object_replicator else [],
                "image_jobs": image_replicator.jobs() if image_replicator else [],
                "image_targets": {c: bool(img_cfg and getattr(img_cfg, c)) for c in ("aws", "azure", "gcp")}}

    @app.post("/dr/replication/pipelines/{name}/{action}", status_code=status.HTTP_201_CREATED)
    def replication_pipeline(name: str, action: str, body: ReasonBody,
                             p: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        if kafka_connect is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Kafka Connect not configured")
        if action not in PIPELINE_ACTIONS:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"action must be one of {PIPELINE_ACTIONS}")
        try:
            names = {c["name"] for c in kafka_connect.connectors()}
        except Exception as exc:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Kafka Connect: {type(exc).__name__}") from None
        if name not in names:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown connector")
        proposal = gate.propose(action_type=ACTION_PIPELINE, target=name,
                                payload={"connector": name, "action": action},
                                reason=f"{action} CDC connector {name}: {body.reason}"[:2000],
                                requested_by=p.subject)
        return _proposal_json(proposal)

    @app.post("/dr/replication/objects/{pair}/plan", status_code=status.HTTP_201_CREATED)
    def replication_object_plan(pair: str, body: ReasonBody,
                                p: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        if object_replicator is None or pair not in object_replicator.pairs:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown object replication pair")
        try:
            plan = object_replicator.plan(pair)
        except Exception as exc:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                                f"could not list the source: {type(exc).__name__}: {str(exc)[:300]}") from None
        if not plan["objects"]:
            raise HTTPException(status.HTTP_409_CONFLICT, "nothing to copy: the target is up to date")
        proposal = gate.propose(action_type=ACTION_OBJECT_SYNC, target=pair,
                                payload={"pair": pair, "objects": plan["objects"]},
                                reason=(f"DR object sync {pair}: {len(plan['objects'])} object(s), "
                                        f"{plan['bytes']} bytes"
                                        f"{' (truncated, more next run)' if plan['truncated'] else ''}"
                                        f": {body.reason}")[:2000],
                                requested_by=p.subject)
        return {**_proposal_json(proposal), "plan": {k: plan[k] for k in ("bytes", "truncated", "missing_at_source")}}

    @app.post("/dr/replication/objects/{pair}/deletions", status_code=status.HTTP_201_CREATED)
    def replication_object_deletions(pair: str, body: ReasonBody,
                                     p: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        if object_replicator is None or pair not in object_replicator.pairs:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown object replication pair")
        try:
            plan = object_replicator.plan_deletions(pair)
        except PermissionError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from None
        except Exception as exc:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                                f"could not check the source: {type(exc).__name__}: {str(exc)[:300]}") from None
        if not plan["keys"]:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "nothing to delete: every replicated object exists at the source")
        payload = {"pair": pair, "keys": plan["keys"]}
        try:
            object_replicator.describe_delete(payload)
        except (PermissionError, ValueError) as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
        proposal = gate.propose(action_type=ACTION_OBJECT_DELETE, target=pair, payload=payload,
                                reason=(f"DR delete replication {pair}: {len(plan['keys'])} object(s) gone at the "
                                        f"source{' (truncated)' if plan['truncated'] else ''}: {body.reason}")[:2000],
                                requested_by=p.subject)
        return {**_proposal_json(proposal), "plan": {k: plan[k] for k in ("truncated", "replicated_objects")}}

    @app.post("/dr/replication/images", status_code=status.HTTP_201_CREATED)
    def replication_image(body: ImageReplicateBody, p: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        if image_replicator is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "image replication not configured")
        try:
            validate_request(body.source_cloud, body.source_id, body.target_cloud, body.name, image_replicator.cfg)
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None
        payload = {"source_cloud": body.source_cloud, "source_id": body.source_id,
                   "target_cloud": body.target_cloud, "name": body.name, "requested_by": p.subject}
        proposal = gate.propose(action_type=ACTION_IMAGE_REPLICATE, target=body.source_id, payload=payload,
                                reason=(f"replicate {body.source_cloud} image to {body.target_cloud}: "
                                        f"{body.reason}")[:2000],
                                requested_by=p.subject)
        return _proposal_json(proposal)

    @app.post("/dr/replication/tags/preview")
    def replication_tag_preview(body: TagPreviewBody, _: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        return map_tags(body.tags, body.target).__dict__

    # ---------------------------------------------------------- generic DR jobs
    jobs_by_kind: dict[str, JobMachine] = dict(dr_jobs or {})

    @app.get("/dr/jobs")
    def dr_jobs_status(_: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        if not jobs_by_kind:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "no DR job module configured")
        return {"modules": [{"kind": k, "title": m.title, "action": m.action, "fields": m.fields(),
                             "summary": m.summary(), "jobs": m.jobs()} for k, m in jobs_by_kind.items()]}

    @app.get("/dr/jobs/{kind}/{job_id}")
    def dr_job_get(kind: str, job_id: str, _: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        m = jobs_by_kind.get(kind)
        if m is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown DR job module")
        try:
            job = m.get(job_id)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found") from None
        if job["kind"] != kind:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
        return job

    @app.post("/dr/jobs/{kind}", status_code=status.HTTP_201_CREATED)
    def dr_job_propose(kind: str, body: DrJobBody, p: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        m = jobs_by_kind.get(kind)
        if m is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown DR job module")
        try:
            clean = m.parse(body.params)
            text = m.describe(clean)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)[:1000]) from None
        proposal = gate.propose(action_type=m.action, target=m.target_of(clean)[:512],
                                payload={**clean, "requested_by": p.subject},
                                reason=f"{m.title}: {text}: {body.reason}"[:2000], requested_by=p.subject)
        return _proposal_json(proposal)

    # ------------------------------------------------------------------ JIT
    def _jit() -> JitService:
        if jit is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "JIT access not configured")
        return jit

    def _jit_call(fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except (LookupError, NotFoundError):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "JIT request not found") from None
        except JitConflictError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
        except (InvalidTransitionError, NotApprovedError, ExpiredError) as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, f"{type(exc).__name__}: {exc}") from None
        except FourEyesViolationError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from None
        except KillSwitchEngagedError as exc:
            raise HTTPException(status.HTTP_423_LOCKED, f"{exc}; retry with POST /jit/requests/{{id}}/grant") from None
        except (JitRequestError, ValueError) as exc:
            raise HTTPException(422, str(exc)) from None

    @app.get("/jit/roles")
    def jit_roles(_: Annotated[Principal, Depends(reader)]) -> list[dict[str, Any]]:
        return [r.model_dump() for r in _jit().catalog.values()]

    @app.post("/jit/requests", status_code=status.HTTP_201_CREATED)
    def jit_request(body: JitRequestBody, p: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        svc = _jit()
        return _jit_call(lambda: svc.request(requester=p.subject, **body.model_dump()))  # type: ignore[no-any-return]

    @app.get("/jit/requests")
    def jit_list(_: Annotated[Principal, Depends(reader)], approval_status: str | None = None,
                 access_status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if approval_status not in (None, "PENDING", "APPROVED", "REJECTED", "EXPIRED"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "unknown approval_status")
        if access_status not in (None, "NONE", "ACTIVE", "REVOKED", "DRY_RUN", "GRANT_FAILED"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "unknown access_status")
        return _jit().list_requests(approval_status=approval_status, access_status=access_status, limit=limit)

    @app.get("/jit/requests/{request_id}")
    def jit_get(request_id: str, _: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        svc = _jit()
        return _jit_call(lambda: svc.get(request_id))  # type: ignore[no-any-return]

    @app.post("/jit/requests/{request_id}/approve")
    def jit_approve(request_id: str, body: DecisionBody,
                    p: Annotated[Principal, Depends(approver)]) -> dict[str, Any]:
        svc = _jit()
        return _jit_call(lambda: svc.approve(request_id, p.subject, body.note))  # type: ignore[no-any-return]

    @app.post("/jit/requests/{request_id}/reject")
    def jit_reject(request_id: str, body: DecisionBody,
                   p: Annotated[Principal, Depends(approver)]) -> dict[str, Any]:
        svc = _jit()
        return _jit_call(lambda: svc.reject(request_id, p.subject, body.note))  # type: ignore[no-any-return]

    @app.post("/jit/requests/{request_id}/grant")
    def jit_grant(request_id: str, p: Annotated[Principal, Depends(approver)]) -> dict[str, Any]:
        svc = _jit()
        return _jit_call(lambda: svc.execute_approved(request_id, p.subject))  # type: ignore[no-any-return]

    @app.post("/jit/requests/{request_id}/revoke")
    def jit_revoke(request_id: str, p: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        svc = _jit()
        current = _jit_call(lambda: svc.get(request_id))
        if not p.has_role(approver_role) and p.subject != current["requested_by"]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "only an approver or the requester can revoke")
        return _jit_call(lambda: svc.revoke_now(request_id, p.subject))  # type: ignore[no-any-return]

    # ------------------------------------------------------------------- DR
    def _dr(stream: str | None = None) -> CircuitBreaker:
        if dr_breaker is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "DR circuit breaker not configured")
        if stream is not None and stream != dr_breaker.stream:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown stream {stream!r}")
        return dr_breaker

    @app.get("/dr/breakers")
    def dr_breakers(_: Annotated[Principal, Depends(reader)]) -> list[dict[str, Any]]:
        b = _dr()
        state, incident, decision = b.store.state(b.stream)
        return [{"stream": b.stream, "state": state, "incident_id": incident, "pending_decision": decision}]

    @app.get("/dr/incidents")
    def dr_incidents(_: Annotated[Principal, Depends(reader)], limit: int = 50) -> list[dict[str, Any]]:
        b = _dr()
        return list_incidents(b.session_factory, b.stream, limit)

    @app.post("/dr/breakers/{stream}/trip")
    def dr_trip(stream: str, body: DrTripBody, p: Annotated[Principal, Depends(approver)]) -> dict[str, Any]:
        b = _dr(stream)
        if b.store.state(stream)[0] == "OPEN":
            raise HTTPException(status.HTTP_409_CONFLICT, "breaker is already OPEN")
        from oplia_ctl.dr.rules import Finding

        incident = b.trip([], [Finding("manual", f"manual trip by {p.subject}: {body.reason}")], None,
                          actor=p.subject)
        return {"stream": stream, "state": "OPEN", "incident_id": incident}

    @app.post("/dr/breakers/{stream}/reset")
    def dr_reset(stream: str, body: DrResetBody, p: Annotated[Principal, Depends(approver)]) -> dict[str, Any]:
        b = _dr(stream)
        try:
            return b.reset(actor=p.subject, decision=body.decision, unlock_targets=body.unlock_targets,
                           note=body.note)
        except ValueError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None

    # ---------------------------------------------------------- governance
    @app.post("/kill-switch")
    def kill_switch(body: KillSwitchBody, p: Annotated[Principal, Depends(approver)]) -> dict[str, Any]:
        gate.set_kill_switch(engaged=body.engaged, actor=p.subject, reason=body.reason)
        return {"engaged": gate.kill_switch_engaged()}

    @app.get("/me")
    def me(p: Annotated[Principal, Depends(principal)]) -> dict[str, Any]:
        """Who the caller is and what the console may offer them (the API still enforces every call)."""
        return {"subject": p.subject, "roles": sorted(p.roles),
                "can": {"approve": p.has_role(approver_role), "operate": p.has_role(operator_role),
                        "read": p.has_role(approver_role) or p.has_role(operator_role)},
                "features": {"aiops": escalation is not None or aiops_engine is not None,
                             "finops": finops_sf is not None, "jit": jit is not None,
                             "inventory": inventory_sf is not None, "databases": db_registry is not None,
                             "consistency": consistency is not None, "integrations": integrations is not None,
                             "network": network is not None, "replication": replication_on,
                             "dr_jobs": bool(jobs_by_kind),
                             "dr": dr_breaker is not None}}

    @app.get("/kill-switch")
    def kill_switch_state(_: Annotated[Principal, Depends(reader)]) -> dict[str, Any]:
        return gate.kill_switch_state()

    @app.get("/audit/events")
    def audit_events(_: Annotated[Principal, Depends(approver)], before_seq: int | None = None,
                     limit: int = 100, proposal_id: str | None = None) -> list[dict[str, Any]]:
        if before_seq is not None and before_seq < 1:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "before_seq must be >= 1")
        return gate.list_audit(before_seq=before_seq, limit=limit, proposal_id=proposal_id)

    @app.get("/audit/verify")
    def audit_verify(_: Annotated[Principal, Depends(approver)]) -> dict[str, bool]:
        return {"intact": gate.verify_audit_chain()}

    return app


def sqlalchemy_ping(engine: Any) -> Callable[[], None]:
    def ping() -> None:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    return ping
