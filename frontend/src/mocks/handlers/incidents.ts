/**
 * SentinelAI — MSW Incident Handlers
 *
 * Mocks: GET /api/v1/incidents, GET /api/v1/incidents/:id,
 *        POST /api/v1/incidents, PATCH /api/v1/incidents/:id
 */

import { http, HttpResponse } from "msw";
import { mockIncidents } from "@/mocks/data/incidents";
import type { IncidentListResponse, IncidentResponse, IncidentUpdatePayload } from "@/types";

const BASE = "/api/v1/incidents";

export const incidentHandlers = [
  // ── GET /api/v1/incidents ────────────────────────────────────────────────
  http.get(BASE + "/", ({ request }) => {
    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get("page") ?? "1", 10);
    const page_size = parseInt(url.searchParams.get("page_size") ?? "25", 10);
    const status = url.searchParams.get("status");
    const assigned_to = url.searchParams.get("assigned_to");

    let items = [...mockIncidents];

    if (status) items = items.filter((i) => i.status === status);
    if (assigned_to) items = items.filter((i) => i.assigned_to === assigned_to);

    const total = items.length;
    const start = (page - 1) * page_size;
    const paged = items.slice(start, start + page_size);

    const data: IncidentListResponse = { total, page, page_size, items: paged };

    return HttpResponse.json({
      success: true,
      message: null,
      data,
      request_id: crypto.randomUUID(),
    });
  }),

  // ── GET /api/v1/incidents/:id ────────────────────────────────────────────
  http.get(`${BASE}/:incidentId`, ({ params }) => {
    const incident = mockIncidents.find((i) => i.id === params.incidentId);
    if (!incident) {
      return HttpResponse.json(
        { success: false, detail: `Incident '${params.incidentId}' not found.` },
        { status: 404 }
      );
    }
    return HttpResponse.json({
      success: true,
      message: null,
      data: incident,
      request_id: crypto.randomUUID(),
    });
  }),

  // ── PATCH /api/v1/incidents/:id ──────────────────────────────────────────
  http.patch(`${BASE}/:incidentId`, async ({ params, request }) => {
    const body = (await request.json()) as IncidentUpdatePayload;
    const incident = mockIncidents.find((i) => i.id === params.incidentId);
    if (!incident) {
      return HttpResponse.json(
        { success: false, detail: `Incident '${params.incidentId}' not found.` },
        { status: 404 }
      );
    }
    const updated: IncidentResponse = {
      ...incident,
      ...body,
      updated_at: new Date().toISOString(),
    };
    return HttpResponse.json({
      success: true,
      message: "Incident updated.",
      data: updated,
      request_id: crypto.randomUUID(),
    });
  }),

  // ── POST /api/v1/incidents/:id/report ───────────────────────────────────
  http.post(`${BASE}/:incidentId/report`, ({ params }) => {
    return HttpResponse.json(
      {
        success: true,
        message: "Report generation started. Check /api/v1/reports for progress.",
        data: { incident_id: params.incidentId },
        request_id: crypto.randomUUID(),
      },
      { status: 202 }
    );
  }),
];
