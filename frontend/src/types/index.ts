/**
 * SentinelAI — Domain Types
 *
 * TypeScript interfaces mirroring the FastAPI Pydantic schemas.
 * Source: backend/app/models/{alert,incident,report,common}.py
 *
 * Naming convention:
 *   - Enums: PascalCase string literal unions (prefer over TS enums for JSON compat)
 *   - Response models: suffix Response (e.g. AlertResponse)
 *   - List models: suffix ListResponse (e.g. AlertListResponse)
 *   - Request payloads: suffix Payload (e.g. AlertStatusUpdatePayload)
 */

// ============================================================
// Common / Envelope
// ============================================================

/** Generic success response envelope from FastAPI. */
export interface ApiResponse<T> {
  success: boolean;
  message: string | null;
  data: T | null;
  request_id: string | null;
}

/** Pagination metadata included in list responses. */
export interface PaginationMeta {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
}

// ============================================================
// Severity & Status Enums
// ============================================================

export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";

export type AlertStatus =
  | "new"
  | "triaging"
  | "open"
  | "in_progress"
  | "escalated"
  | "resolved"
  | "false_positive"
  | "suppressed";

export type AlertSource =
  | "firewall"
  | "ids"
  | "ips"
  | "edr"
  | "siem"
  | "waf"
  | "cloud"
  | "auth"
  | "network"
  | "custom";

export type IncidentSeverity = "critical" | "high" | "medium" | "low";

export type IncidentStatus =
  | "open"
  | "investigating"
  | "contained"
  | "eradicated"
  | "recovered"
  | "closed"
  | "false_positive";

export type ReportFormat = "markdown" | "pdf" | "both";

// ============================================================
// MITRE ATT&CK
// ============================================================

/** A single MITRE ATT&CK TTP annotation on an alert. */
export interface MitreMapping {
  tactic: string;
  tactic_id: string;
  technique: string;
  technique_id: string;
  sub_technique: string | null;
  sub_technique_id: string | null;
  confidence: number; // 0.0 - 1.0
  mapping_method: "rule_based" | "semantic" | "llm_inferred";
  rationale: string | null;
}

/** Lightweight MITRE technique used in the ATT&CK explorer. */
export interface MitreTechnique {
  id: string; // e.g. "T1059"
  name: string;
  tactic: string;
  tactic_id: string;
  description: string;
  sub_techniques: MitreSubTechnique[];
  covered: boolean; // does SentinelAI have detections for this?
  alert_count: number;
}

export interface MitreSubTechnique {
  id: string; // e.g. "T1059.001"
  name: string;
  description: string;
  covered: boolean;
  alert_count: number;
}

export interface MitreTactic {
  id: string; // e.g. "TA0002"
  name: string;
  techniques: MitreTechnique[];
}

// ============================================================
// Alert Enrichment & Triage
// ============================================================

export interface EntityInfo {
  hostname: string | null;
  ip_address: string | null;
  username: string | null;
  department: string | null;
  role: string | null;
  is_privileged: boolean;
  asset_criticality: "critical" | "high" | "medium" | "low" | null;
}

export interface IOCInfo {
  value: string;
  ioc_type: "ip" | "domain" | "hash" | "url";
  reputation_score: number | null;
  malicious: boolean | null;
  sources: string[];
  tags: string[];
}

export interface EnrichmentData {
  entity: EntityInfo | null;
  iocs: IOCInfo[];
  correlated_event_count: number;
  baseline_deviation_score: number | null;
  pre_llm_risk_score: number | null;
  enriched_at: string | null; // ISO 8601
}

export interface TriageResult {
  severity: Severity;
  priority_rank: number; // 1 = highest
  false_positive_probability: number; // 0.0 - 1.0
  confidence: number; // 0.0 - 1.0
  classification: string;
  summary: string;
  recommended_actions: string[];
  analyst_questions: string[];
  triaged_at: string; // ISO 8601
  model_used: string;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  latency_ms: number | null;
}

// ============================================================
// Alert
// ============================================================

/** Complete alert document returned by GET /api/v1/alerts/{id} */
export interface AlertResponse {
  id: string;
  source: AlertSource;
  source_alert_id: string | null;
  title: string;
  description: string;
  status: AlertStatus;
  severity: Severity | null;
  source_timestamp: string | null; // ISO 8601
  ingested_at: string; // ISO 8601
  host: string | null;
  ip_address: string | null;
  username: string | null;
  tags: string[];
  enrichment: EnrichmentData | null;
  mitre_mappings: MitreMapping[];
  triage: TriageResult | null;
  incident_id: string | null;
}

/** Paginated alert list response. */
export interface AlertListResponse {
  total: number;
  page: number;
  page_size: number;
  items: AlertResponse[];
}

/** Payload for PUT /api/v1/alerts/{id}/status */
export interface AlertStatusUpdatePayload {
  status: AlertStatus;
  comment: string | null;
}

// ============================================================
// Incident
// ============================================================

/** A single timeline entry in an incident. */
export interface TimelineEntry {
  timestamp: string; // ISO 8601
  event_type: "alert" | "action" | "note" | "status_change";
  actor: string | null; // user_id or "system"
  description: string;
  reference_id: string | null;
}

/** Complete incident document returned by GET /api/v1/incidents/{id} */
export interface IncidentResponse {
  id: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  alert_ids: string[];
  created_at: string; // ISO 8601
  updated_at: string; // ISO 8601
  created_by: string;
  assigned_to: string | null;
  tags: string[];
  timeline: TimelineEntry[];
  resolution_notes: string | null;
  report_id: string | null;
}

/** Paginated incident list. */
export interface IncidentListResponse {
  total: number;
  page: number;
  page_size: number;
  items: IncidentResponse[];
}

/** Payload for PATCH /api/v1/incidents/{id} */
export interface IncidentUpdatePayload {
  title?: string;
  description?: string;
  severity?: IncidentSeverity;
  status?: IncidentStatus;
  assigned_to?: string | null;
  resolution_notes?: string | null;
}

/** Payload for POST /api/v1/incidents */
export interface IncidentCreatePayload {
  title: string;
  description: string;
  severity: IncidentSeverity;
  alert_ids: string[];
  assigned_to?: string | null;
  tags?: string[];
}

// ============================================================
// Reports
// ============================================================

export interface ReportMetadata {
  report_id: string;
  incident_id: string;
  title: string;
  generated_at: string; // ISO 8601
  analyst_name: string;
  format: ReportFormat;
  has_pdf: boolean;
  word_count: number;
}

export interface ReportResult extends ReportMetadata {
  markdown_content: string;
}

export interface ReportRequestPayload {
  incident_id: string;
  analyst_name?: string;
  format?: ReportFormat;
}

// ============================================================
// Analyst Copilot / Chat
// ============================================================

export type ChatRole = "user" | "assistant" | "system";

export interface ChatMessage {
  role: ChatRole;
  content: string;
  timestamp?: string; // ISO 8601, added client-side for display
}

/** Request payload for POST /api/v1/chat/message */
export interface ChatRequestPayload {
  session_id: string | null;
  message: string;
  alert_context_id: string | null;
  incident_context_id: string | null;
}

/** Response from POST /api/v1/chat/message */
export interface ChatResponse {
  session_id: string;
  message: string;
  role: "assistant";
  citations: Array<{ id: string; type: string; title: string }>;
  suggested_queries: string[];
  tokens_used: number | null;
}

/** A stored chat session in history. */
export interface ChatSession {
  session_id: string;
  created_at: string; // ISO 8601
  last_message_at: string;
  message_count: number;
  preview: string; // first user message truncated
  alert_context_id: string | null;
  incident_context_id: string | null;
}

// ============================================================
// Dashboard (aggregated / computed)
// ============================================================

export interface DashboardStats {
  critical_alerts: number;
  open_alerts: number;
  active_incidents: number;
  mitre_coverage_percent: number;
  risk_score: number; // 0–100
  alerts_last_24h: number;
  alerts_change_percent: number; // vs previous 24h
}

export interface RiskTrendPoint {
  timestamp: string; // ISO 8601
  risk_score: number;
  alert_count: number;
}

export interface TopHost {
  hostname: string;
  ip_address: string;
  alert_count: number;
  severity: Severity;
  last_seen: string;
}

export interface RecentInvestigation {
  id: string;
  type: "alert" | "incident";
  title: string;
  status: AlertStatus | IncidentStatus;
  severity: Severity | IncidentSeverity;
  updated_at: string;
  assignee: string | null;
}

// ============================================================
// UI-only types (not from backend)
// ============================================================

/** Generic sort direction for tables. */
export type SortDirection = "asc" | "desc";

/** Column sort state for data tables. */
export interface SortState<T extends string = string> {
  column: T;
  direction: SortDirection;
}

/** Filter state for the alerts table. */
export interface AlertFilters {
  search: string;
  severity: Severity | "";
  status: AlertStatus | "";
  source: AlertSource | "";
  page: number;
  page_size: number;
}

/** Filter state for the incidents list. */
export interface IncidentFilters {
  status: IncidentStatus | "";
  severity: IncidentSeverity | "";
  assigned_to: string;
  page: number;
  page_size: number;
}
