/**
 * SentinelAI — MSW Alert Handlers
 *
 * Mocks: GET /api/v1/alerts, GET /api/v1/alerts/:id,
 *        PUT /api/v1/alerts/:id/status, POST /api/v1/alerts/:id/triage
 */

import { http, HttpResponse } from "msw";
import { mockAlerts } from "@/mocks/data/alerts";
import type { AlertListResponse, AlertResponse, AlertStatusUpdatePayload } from "@/types";

const BASE = "/api/v1/alerts";

export const alertHandlers = [
  // ── GET /api/v1/alerts ───────────────────────────────────────────────────
  http.get(BASE + "/", ({ request }) => {
    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get("page") ?? "1", 10);
    const page_size = parseInt(url.searchParams.get("page_size") ?? "25", 10);
    const severity = url.searchParams.get("severity");
    const status = url.searchParams.get("status");
    const source = url.searchParams.get("source");
    const search = url.searchParams.get("search")?.toLowerCase();

    let items = [...mockAlerts];

    if (severity) items = items.filter((a) => a.severity === severity);
    if (status) items = items.filter((a) => a.status === status);
    if (source) items = items.filter((a) => a.source === source);
    if (search) {
      items = items.filter(
        (a) =>
          a.title.toLowerCase().includes(search) ||
          a.description.toLowerCase().includes(search) ||
          a.host?.toLowerCase().includes(search) ||
          a.id.toLowerCase().includes(search)
      );
    }

    const total = items.length;
    const start = (page - 1) * page_size;
    const paged = items.slice(start, start + page_size);

    const data: AlertListResponse = { total, page, page_size, items: paged };

    return HttpResponse.json({
      success: true,
      message: null,
      data,
      request_id: crypto.randomUUID(),
    });
  }),

  // ── GET /api/v1/alerts/:id ───────────────────────────────────────────────
  http.get(`${BASE}/:alertId`, ({ params }) => {
    const alert = mockAlerts.find((a) => a.id === params.alertId);
    if (!alert) {
      return HttpResponse.json(
        { success: false, detail: `Alert '${params.alertId}' not found.` },
        { status: 404 }
      );
    }
    return HttpResponse.json({
      success: true,
      message: null,
      data: alert,
      request_id: crypto.randomUUID(),
    });
  }),

  // ── PUT /api/v1/alerts/:id/status ────────────────────────────────────────
  http.put(`${BASE}/:alertId/status`, async ({ params, request }) => {
    const body = (await request.json()) as AlertStatusUpdatePayload;
    const alert = mockAlerts.find((a) => a.id === params.alertId);
    if (!alert) {
      return HttpResponse.json(
        { success: false, detail: `Alert '${params.alertId}' not found.` },
        { status: 404 }
      );
    }
    const updated: AlertResponse = { ...alert, status: body.status };
    return HttpResponse.json({
      success: true,
      message: `Alert status updated to ${body.status}.`,
      data: updated,
      request_id: crypto.randomUUID(),
    });
  }),

  // ── POST /api/v1/alerts/:id/triage ──────────────────────────────────────
  http.post(`${BASE}/:alertId/triage`, ({ params }) => {
    const alert = mockAlerts.find((a) => a.id === params.alertId);
    if (!alert) {
      return HttpResponse.json(
        { success: false, detail: `Alert '${params.alertId}' not found.` },
        { status: 404 }
      );
    }
    return HttpResponse.json(
      {
        success: true,
        message: "Triage pipeline triggered. Results will appear shortly.",
        data: alert,
        request_id: crypto.randomUUID(),
      },
      { status: 202 }
    );
  }),
];
