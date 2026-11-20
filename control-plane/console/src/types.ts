export interface Me {
  subject: string;
  roles: string[];
  can: { approve: boolean; operate: boolean; read: boolean };
  features: { aiops: boolean; finops: boolean; jit: boolean; dr: boolean; inventory?: boolean; databases?: boolean; consistency?: boolean; integrations?: boolean; network?: boolean; replication?: boolean; dr_jobs?: boolean };
}

export type ProposalStatus =
  | "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "EXECUTING" | "EXECUTED" | "DRY_RUN" | "FAILED";
export const PROPOSAL_STATUSES: ProposalStatus[] = [
  "PENDING", "APPROVED", "EXECUTING", "EXECUTED", "DRY_RUN", "FAILED", "REJECTED", "EXPIRED",
];

export interface Proposal {
  id: string;
  action_type: string;
  target: string;
  payload: unknown;
  reason: string;
  requested_by: string;
  status: ProposalStatus;
  created_at: string;
  expires_at: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  executed_at: string | null;
  result: unknown;
}

export interface KillSwitch {
  engaged: boolean;
  set_by: string | null;
  set_at: string | null;
  reason: string | null;
}

export interface AuditEvent {
  seq: number;
  ts: string;
  actor: string;
  event: string;
  proposal_id: string | null;
  detail: unknown;
  hash: string;
}

export interface Breaker {
  stream: string;
  state: "CLOSED" | "OPEN";
  incident_id: string | null;
  pending_decision: string | null;
}

export interface Incident {
  id: string;
  stream: string;
  opened_at: string;
  trigger: string;
  summary: string;
  findings: unknown;
  positions: unknown;
  dump_path: string | null;
  dump_sha256: string | null;
  actions: Record<string, unknown>;
  resolved_at: string | null;
  resolved_by: string | null;
  resolution: unknown;
}

export interface Finding {
  id: string;
  cloud: string;
  scope: string;
  region: string | null;
  category: string;
  resource_type: string;
  resource_id: string;
  name: string | null;
  missing: string[];
  wrong_case: unknown;
  invalid: unknown;
  owner_hint: string | null;
  status: "OPEN" | "RESOLVED";
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  resolution: string | null;
}

export interface Scan {
  id: string;
  started_at: string;
  finished_at: string | null;
  resources_scanned: number;
  noncompliant: number;
  new_findings: number;
  resolved_findings: number;
  source_errors: unknown;
  alert: unknown;
}

export interface Candidate {
  id: string;
  cloud: string;
  kind: string;
  resource_id: string;
  size: string | null;
  first_seen_idle_at: string;
  last_seen_idle_at: string;
  proposal_id: string | null;
}

export interface JitRole {
  role: string;
  description: string;
  idp: string;
  group_ref: string;
  max_minutes: number;
  target_cloud_accounts: string[];
}

export interface JitRequest {
  id: string;
  user_id: string;
  requested_role: string;
  target_cloud_account: string;
  expiration_minutes: number;
  approval_status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";
  access_status: "NONE" | "ACTIVE" | "REVOKED" | "DRY_RUN" | "GRANT_FAILED";
  idp: string;
  group_ref: string;
  justification: string;
  requested_by: string;
  proposal_id: string | null;
  created_at: string;
  decided_at: string | null;
  decided_by: string | null;
  granted_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
  revoke_attempts: number;
  last_error: string | null;
}

export interface Prediction {
  id: string;
  risk_id: string;
  service: string;
  severity: string;
  probability: number;
  predicted_at: string;
  notify_at: string;
  summary: string;
  status: string;
  attempts: number;
  channels: string[];
  escalated_at: string | null;
  last_error: string | null;
}

export interface Instance {
  id: string;
  cloud: "aws" | "azure" | "gcp" | "ibm";
  scope: string;
  region: string;
  resource_type: string;
  resource_id: string;
  name: string;
  size: string | null;
  state: string | null;
  tags: Record<string, string>;
  tag_compliant: boolean;
  tag_issues: string[];
  first_seen_at: string;
  last_seen_at: string;
  gone_at: string | null;
}

export interface InventoryScan {
  id: string;
  started_at: string;
  finished_at: string | null;
  instances_seen: number;
  new_instances: number;
  gone_instances: number;
  source_errors: { source: string; error: string }[];
}

export interface DbCheck {
  checked_at: string;
  ok: boolean;
  latency_ms: number | null;
  detail: { version?: string; role?: string; read_only?: boolean; replication?: Record<string, unknown> };
  error: string | null;
  triggered_by: string;
}

export interface DatabaseEntry {
  name: string;
  engine: "postgres" | "mysql" | "mongodb" | "cockroachdb";
  cloud: string;
  role: "primary" | "dr" | "replica";
  database: string | null;
  dr_of: string | null;
  description: string;
  last_check: DbCheck | null;
}

export interface ConsistencyTable {
  source_rows: number;
  target_rows: number;
  match: boolean;
  checksum?: string;
  rechecked?: boolean;
}

export interface ConsistencyRun {
  id: string;
  pair: string;
  status: "CONSISTENT" | "DRIFT" | "FAILED";
  summary: string;
  report: {
    source?: string;
    target?: string;
    schema?: { table: string; issue: string }[];
    tables?: Record<string, ConsistencyTable>;
    lag_seconds?: number | null;
    dr_breaker?: { stream: string; state: string; incident_id: string | null };
    error?: string;
  };
  triggered_by: string;
  proposal_id: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface IntegrationStatus {
  name: string;
  category: "cloud" | "cicd" | "identity" | "alerting" | "secrets" | "sign-in";
  target: string;
  secrets: string[];
  status: "ok" | "configured" | "error" | "not_configured";
  detail: string;
  can_test_notification: boolean;
  checked_at: string;
  latency_ms: number;
}

export interface NetSection<T> { configured: boolean; ok: boolean; items: T[]; error: string | null; latency_ms: number }
export interface EndpointGroup {
  key: string; arn: string; region?: string; traffic_dial?: number; health_check?: string; error?: string;
  all_healthy: boolean;
  endpoints: { endpoint_id: string; weight: number | null; health: string; health_reason: string }[];
}
export interface DxConnection {
  region: string; id: string; name: string; state: string; partner: string; bandwidth: string; location: string;
  virtual_interfaces: { id: string; name: string; type: string; state: string; vlan: number; bgp: string[] }[];
}
export interface ConsulPeering { name: string; state: string; peer_server_name: string; imported_services: number; exported_services: number; last_heartbeat: string | null }
export interface LinkerdLink { name: string; namespace: string; target_cluster: string; gateway: string; mirrored_services: number; not_ready: string[] }
export interface NetworkStatus {
  global_accelerator: NetSection<EndpointGroup>;
  direct_connect: NetSection<DxConnection>;
  consul: NetSection<ConsulPeering>;
  linkerd: NetSection<LinkerdLink>;
  dial_history: { group: string; from: number; to: number; executed_at: string; request_id: string | null }[];
  policy: { max_increase: number; min_hold_minutes: number };
}

export interface Connector { name: string; type: string; class: string; state: string; worker: string; failed_tasks: number; tasks: { id: number; state: string; trace: string }[] }
export interface ObjectPairStatus {
  pair: string; source: string; target: string; target_key: string | null; replicated_objects: number;
  replicate_deletions?: boolean;
  last_run: null | { status: string; started_at: string; copied: number; bytes: number; summary: { kind?: "delete"; deleted?: string[]; skipped: { key: string; reason: string }[]; failed: { key: string; error: string }[] } };
}
export interface ImageJob { id: string; source_cloud: string; source_id: string; target_cloud: string; name: string; status: string; step: string; error: string | null; created_at: string; updated_at: string; state: Record<string, unknown> }
export interface ReplicationStatus {
  pipelines: { configured: boolean; ok: boolean; items: Connector[]; error: string | null };
  object_pairs: ObjectPairStatus[];
  image_jobs: ImageJob[];
  image_targets: { aws: boolean; azure: boolean; gcp: boolean };
}
export interface TagMap { tags: Record<string, string>; changes: string[]; dropped: string[] }

export interface DrJob { id: string; kind: string; target: string; status: string; step: string; payload: Record<string, unknown>; state: Record<string, unknown>; error: string | null; requested_by: string; created_at: string; updated_at: string }
export interface DrJobModule { kind: string; title: string; action: string; fields: import("./components/ui").Field[]; summary: Record<string, unknown>; jobs: DrJob[] }
export interface DrJobsStatus { modules: DrJobModule[] }
