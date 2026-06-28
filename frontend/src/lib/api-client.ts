/**
 * SentinelAI — Typed API Client
 *
 * A thin fetch wrapper that:
 *  - Prepends the base URL (/api/v1)
 *  - Attaches the Bearer token from localStorage
 *  - Unwraps the SuccessResponse<T> envelope
 *  - Throws ApiError on non-2xx responses
 *
 * Usage:
 *   const data = await apiClient.get<AlertListResponse>("/alerts?page=1");
 *   const alert = await apiClient.post<AlertResponse>("/alerts/ingest", payload);
 */

import type { ApiResponse } from "@/types";

// ── Constants ──────────────────────────────────────────────────────────────

const BASE_URL = "/api/v1";

// ── Error class ────────────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly detail: string,
    public readonly requestId?: string
  ) {
    super(`[${status}] ${detail}`);
    this.name = "ApiError";
  }
}

// ── Auth helper ────────────────────────────────────────────────────────────

function getAuthHeaders(): HeadersInit {
  const token = localStorage.getItem("sentinel_token");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

// ── Core fetch wrapper ─────────────────────────────────────────────────────

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  options?: RequestInit
): Promise<T> {
  const url = `${BASE_URL}${path}`;

  const response = await fetch(url, {
    method,
    headers: getAuthHeaders(),
    body: body !== undefined ? JSON.stringify(body) : undefined,
    ...options,
  });

  // Handle 204 No Content
  if (response.status === 204) {
    return undefined as unknown as T;
  }

  let json: unknown;
  try {
    json = await response.json();
  } catch {
    throw new ApiError(response.status, "Failed to parse response body");
  }

  if (!response.ok) {
    const err = json as { detail?: string; message?: string; request_id?: string };
    throw new ApiError(
      response.status,
      err.detail ?? err.message ?? "Unknown error",
      err.request_id
    );
  }

  // Unwrap SuccessResponse<T> envelope
  const envelope = json as ApiResponse<T>;
  if (envelope.data !== undefined && envelope.data !== null) {
    return envelope.data;
  }

  // Some endpoints return the full envelope (e.g. paginated list inside data)
  return json as T;
}

// ── Public API ─────────────────────────────────────────────────────────────

export const apiClient = {
  get<T>(path: string, options?: RequestInit): Promise<T> {
    return request<T>("GET", path, undefined, options);
  },

  post<T>(path: string, body?: unknown, options?: RequestInit): Promise<T> {
    return request<T>("POST", path, body, options);
  },

  put<T>(path: string, body?: unknown, options?: RequestInit): Promise<T> {
    return request<T>("PUT", path, body, options);
  },

  patch<T>(path: string, body?: unknown, options?: RequestInit): Promise<T> {
    return request<T>("PATCH", path, body, options);
  },

  delete<T = void>(path: string, options?: RequestInit): Promise<T> {
    return request<T>("DELETE", path, undefined, options);
  },
};

// ── Query key factory ──────────────────────────────────────────────────────
// Centralised TanStack Query key definitions to avoid string duplication.

export const queryKeys = {
  // Alerts
  alerts: {
    all: ["alerts"] as const,
    list: (filters: Record<string, unknown>) => ["alerts", "list", filters] as const,
    detail: (id: string) => ["alerts", "detail", id] as const,
  },

  // Incidents
  incidents: {
    all: ["incidents"] as const,
    list: (filters: Record<string, unknown>) => ["incidents", "list", filters] as const,
    detail: (id: string) => ["incidents", "detail", id] as const,
  },

  // Reports
  reports: {
    all: ["reports"] as const,
    detail: (id: string) => ["reports", "detail", id] as const,
  },

  // Chat
  chat: {
    history: (sessionId: string) => ["chat", "history", sessionId] as const,
  },

  // Dashboard
  dashboard: {
    stats: ["dashboard", "stats"] as const,
    riskTrend: ["dashboard", "risk-trend"] as const,
    topHosts: ["dashboard", "top-hosts"] as const,
  },

  // MITRE
  mitre: {
    matrix: ["mitre", "matrix"] as const,
    technique: (id: string) => ["mitre", "technique", id] as const,
  },
} as const;
