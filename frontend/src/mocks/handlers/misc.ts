/**
 * SentinelAI — MSW Dashboard, Chat & MITRE Handlers
 */

import { http, HttpResponse } from "msw";
import {
  mockDashboardStats,
  mockRiskTrend,
  mockTopHosts,
  mockRecentInvestigations,
  mockMitreMatrix,
} from "@/mocks/data/dashboard";
import type { ChatRequestPayload, ChatResponse } from "@/types";

// ── Dashboard stats ────────────────────────────────────────────────────────

export const dashboardHandlers = [
  http.get("/api/v1/dashboard/stats", () => {
    return HttpResponse.json({
      success: true,
      message: null,
      data: mockDashboardStats,
      request_id: crypto.randomUUID(),
    });
  }),

  http.get("/api/v1/dashboard/risk-trend", () => {
    return HttpResponse.json({
      success: true,
      message: null,
      data: mockRiskTrend,
      request_id: crypto.randomUUID(),
    });
  }),

  http.get("/api/v1/dashboard/top-hosts", () => {
    return HttpResponse.json({
      success: true,
      message: null,
      data: mockTopHosts,
      request_id: crypto.randomUUID(),
    });
  }),

  http.get("/api/v1/dashboard/recent-investigations", () => {
    return HttpResponse.json({
      success: true,
      message: null,
      data: mockRecentInvestigations,
      request_id: crypto.randomUUID(),
    });
  }),
];

// ── MITRE ATT&CK ──────────────────────────────────────────────────────────

export const mitreHandlers = [
  http.get("/api/v1/mitre/matrix", () => {
    return HttpResponse.json({
      success: true,
      message: null,
      data: mockMitreMatrix,
      request_id: crypto.randomUUID(),
    });
  }),

  http.get("/api/v1/mitre/technique/:techniqueId", ({ params }) => {
    const allTechniques = mockMitreMatrix.flatMap((t) => t.techniques);
    const technique = allTechniques.find((t) => t.id === params.techniqueId);
    if (!technique) {
      return HttpResponse.json(
        { success: false, detail: `Technique '${params.techniqueId}' not found.` },
        { status: 404 }
      );
    }
    return HttpResponse.json({
      success: true,
      message: null,
      data: technique,
      request_id: crypto.randomUUID(),
    });
  }),
];

// ── Analyst Copilot / Chat ─────────────────────────────────────────────────

const COPILOT_REPLIES: Record<string, string> = {
  default:
    "I've analysed the context. Based on the alert pattern, this appears consistent " +
    "with a Cobalt Strike stager. I recommend isolating the affected host immediately " +
    "and running a memory forensics capture before pulling the network plug.",
  powershell:
    "The encoded PowerShell command decodes to a standard AMSI bypass followed by a " +
    "reflective DLL injection loader. The target domain `update-cdn.systems` resolved " +
    "to a DigitalOcean IP at the time of execution.",
  ioc: "185.220.101.47 is a confirmed Tor exit node listed in AbuseIPDB with 98% abuse " +
    "confidence. It has been associated with Cobalt Strike C2 activity in the past 30 days.",
};

function getReply(message: string): string {
  const lower = message.toLowerCase();
  if (lower.includes("powershell") || lower.includes("encoded")) return COPILOT_REPLIES.powershell;
  if (lower.includes("ioc") || lower.includes("185.220")) return COPILOT_REPLIES.ioc;
  return COPILOT_REPLIES.default;
}

export const chatHandlers = [
  http.post("/api/v1/chat/message", async ({ request }) => {
    const body = (await request.json()) as ChatRequestPayload;
    const session_id = body.session_id ?? crypto.randomUUID();

    // Simulate ~400ms LLM latency
    await new Promise((r) => setTimeout(r, 400));

    const response: ChatResponse = {
      session_id,
      message: getReply(body.message),
      role: "assistant",
      citations: body.alert_context_id
        ? [{ id: body.alert_context_id, type: "alert", title: "Related Alert" }]
        : [],
      suggested_queries: [
        "What MITRE techniques are associated with this alert?",
        "Is the host DC01 involved in any other incidents?",
        "Decode the PowerShell payload for me",
      ],
      tokens_used: Math.floor(Math.random() * 800) + 400,
    };

    return HttpResponse.json({
      success: true,
      message: null,
      data: response,
      request_id: crypto.randomUUID(),
    });
  }),

  http.get("/api/v1/chat/history/:sessionId", () => {
    return HttpResponse.json({
      success: true,
      message: null,
      data: [],
      request_id: crypto.randomUUID(),
    });
  }),

  http.delete("/api/v1/chat/session/:sessionId", () => {
    return new HttpResponse(null, { status: 204 });
  }),
];
