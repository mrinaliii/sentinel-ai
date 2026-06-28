/**
 * SentinelAI — Mock Incident Data
 *
 * Realistic IncidentResponse fixtures mirroring the FastAPI backend models.
 */

import type { IncidentResponse } from "@/types";

export const mockIncidents: IncidentResponse[] = [
  {
    id: "inc-0001",
    title: "Ransomware pre-staging campaign on finance subnet",
    description:
      "Coordinated attack chain detected on the finance network segment. " +
      "Initial access via phishing, followed by lateral movement using PsExec " +
      "and a domain controller compromise. Cobalt Strike C2 beacon confirmed.",
    severity: "critical",
    status: "investigating",
    alert_ids: ["a1b2c3d4-0001", "a1b2c3d4-0004"],
    created_at: "2026-06-28T20:05:00Z",
    updated_at: "2026-06-28T20:30:00Z",
    created_by: "system",
    assigned_to: "analyst@acme.com",
    tags: ["ransomware", "lateral-movement", "finance", "critical-asset"],
    timeline: [
      {
        timestamp: "2026-06-28T19:31:00Z",
        event_type: "alert",
        actor: "system",
        description: "Alert a1b2c3d4-0001 triggered: Suspicious PowerShell execution on DC01",
        reference_id: "a1b2c3d4-0001",
      },
      {
        timestamp: "2026-06-28T20:02:00Z",
        event_type: "alert",
        actor: "system",
        description: "Alert a1b2c3d4-0004 triggered: PsExec lateral movement on FIN-WS-014",
        reference_id: "a1b2c3d4-0004",
      },
      {
        timestamp: "2026-06-28T20:05:00Z",
        event_type: "status_change",
        actor: "system",
        description: "Incident created and assigned to analyst@acme.com",
        reference_id: null,
      },
      {
        timestamp: "2026-06-28T20:15:00Z",
        event_type: "action",
        actor: "analyst@acme.com",
        description: "Network isolation applied to DC01.corp.acme.com via EDR policy",
        reference_id: null,
      },
      {
        timestamp: "2026-06-28T20:20:00Z",
        event_type: "note",
        actor: "analyst@acme.com",
        description:
          "Memory forensics initiated on DC01. Cobalt Strike beacon found in svchost.exe at PID 3420. " +
          "Watermark matches CS4 licensed version. C2 domain: update-cdn.systems.",
        reference_id: null,
      },
      {
        timestamp: "2026-06-28T20:30:00Z",
        event_type: "status_change",
        actor: "analyst@acme.com",
        description: "Status changed from OPEN → INVESTIGATING",
        reference_id: null,
      },
    ],
    resolution_notes: null,
    report_id: null,
  },
  {
    id: "inc-0002",
    title: "External password spray against VPN gateway",
    description:
      "Sustained credential spray campaign targeting VPN from a known botnet IP cluster. " +
      "Over 2,000 login attempts in 30 minutes. No successful authentications confirmed.",
    severity: "high",
    status: "contained",
    alert_ids: ["a1b2c3d4-0002"],
    created_at: "2026-06-28T19:00:00Z",
    updated_at: "2026-06-28T19:45:00Z",
    created_by: "analyst@acme.com",
    assigned_to: "analyst@acme.com",
    tags: ["brute-force", "vpn", "external"],
    timeline: [
      {
        timestamp: "2026-06-28T18:55:00Z",
        event_type: "alert",
        actor: "system",
        description: "Alert triggered: 500+ failed auth attempts on VPN gateway",
        reference_id: "a1b2c3d4-0002",
      },
      {
        timestamp: "2026-06-28T19:00:00Z",
        event_type: "status_change",
        actor: "analyst@acme.com",
        description: "Incident created",
        reference_id: null,
      },
      {
        timestamp: "2026-06-28T19:20:00Z",
        event_type: "action",
        actor: "analyst@acme.com",
        description: "ASN block applied to AS202425 at perimeter firewall",
        reference_id: null,
      },
      {
        timestamp: "2026-06-28T19:45:00Z",
        event_type: "status_change",
        actor: "analyst@acme.com",
        description: "Status changed to CONTAINED — spray traffic stopped",
        reference_id: null,
      },
    ],
    resolution_notes:
      "Blocked originating ASN. No successful authentications observed. " +
      "Recommend enabling geo-blocking for countries with no business operations.",
    report_id: null,
  },
  {
    id: "inc-0003",
    title: "AWS IAM privilege escalation in production account",
    description:
      "CI/CD service account 'ci-deploy-prod' attached AdministratorAccess policy " +
      "to an IAM role at 02:14 UTC outside of deployment windows. Possible supply chain compromise.",
    severity: "critical",
    status: "open",
    alert_ids: ["a1b2c3d4-0003"],
    created_at: "2026-06-28T02:30:00Z",
    updated_at: "2026-06-28T02:30:00Z",
    created_by: "system",
    assigned_to: null,
    tags: ["cloud", "iam", "aws", "supply-chain"],
    timeline: [
      {
        timestamp: "2026-06-28T02:14:00Z",
        event_type: "alert",
        actor: "system",
        description: "GuardDuty alert: IAM policy modification by ci-deploy-prod",
        reference_id: "a1b2c3d4-0003",
      },
      {
        timestamp: "2026-06-28T02:30:00Z",
        event_type: "status_change",
        actor: "system",
        description: "Incident auto-created from critical alert cluster",
        reference_id: null,
      },
    ],
    resolution_notes: null,
    report_id: null,
  },
];
