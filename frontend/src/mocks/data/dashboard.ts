/**
 * SentinelAI — Mock Dashboard & MITRE Data
 *
 * Aggregate stats and MITRE ATT&CK matrix fixtures.
 */

import type {
  DashboardStats,
  MitreTactic,
  RiskTrendPoint,
  TopHost,
  RecentInvestigation,
} from "@/types";

// ── Dashboard stats ────────────────────────────────────────────────────────

export const mockDashboardStats: DashboardStats = {
  critical_alerts: 3,
  open_alerts: 12,
  active_incidents: 2,
  mitre_coverage_percent: 61,
  risk_score: 78,
  alerts_last_24h: 47,
  alerts_change_percent: 0.23, // +23% vs previous day
};

// ── Risk trend (7 days, hourly granularity abbreviated to key points) ──────

function hoursAgo(h: number): string {
  return new Date(Date.now() - h * 3600 * 1000).toISOString();
}

export const mockRiskTrend: RiskTrendPoint[] = [
  { timestamp: hoursAgo(168), risk_score: 42, alert_count: 8 },
  { timestamp: hoursAgo(144), risk_score: 38, alert_count: 6 },
  { timestamp: hoursAgo(120), risk_score: 51, alert_count: 12 },
  { timestamp: hoursAgo(96), risk_score: 47, alert_count: 10 },
  { timestamp: hoursAgo(72), risk_score: 44, alert_count: 9 },
  { timestamp: hoursAgo(48), risk_score: 59, alert_count: 16 },
  { timestamp: hoursAgo(36), risk_score: 55, alert_count: 14 },
  { timestamp: hoursAgo(24), risk_score: 63, alert_count: 19 },
  { timestamp: hoursAgo(18), risk_score: 70, alert_count: 24 },
  { timestamp: hoursAgo(12), risk_score: 74, alert_count: 31 },
  { timestamp: hoursAgo(6), risk_score: 78, alert_count: 47 },
  { timestamp: hoursAgo(0), risk_score: 78, alert_count: 47 },
];

// ── Top hosts ──────────────────────────────────────────────────────────────

export const mockTopHosts: TopHost[] = [
  { hostname: "DC01.corp.acme.com", ip_address: "10.0.0.5", alert_count: 14, severity: "critical", last_seen: hoursAgo(1) },
  { hostname: "FIN-WS-014", ip_address: "10.10.5.14", alert_count: 9, severity: "critical", last_seen: hoursAgo(2) },
  { hostname: "WORKSTATION-207", ip_address: "10.20.1.207", alert_count: 6, severity: "high", last_seen: hoursAgo(4) },
  { hostname: "vpn-gw01.corp.acme.com", ip_address: "10.0.0.20", alert_count: 5, severity: "high", last_seen: hoursAgo(5) },
  { hostname: "SALES-WS-003", ip_address: "10.30.2.3", alert_count: 3, severity: "medium", last_seen: hoursAgo(12) },
];

// ── Recent investigations ──────────────────────────────────────────────────

export const mockRecentInvestigations: RecentInvestigation[] = [
  { id: "inc-0001", type: "incident", title: "Ransomware pre-staging campaign on finance subnet", status: "investigating", severity: "critical", updated_at: hoursAgo(0.5), assignee: "analyst@acme.com" },
  { id: "a1b2c3d4-0003", type: "alert", title: "IAM role privilege escalation via policy attachment", status: "triaging", severity: "critical", updated_at: hoursAgo(1), assignee: null },
  { id: "inc-0002", type: "incident", title: "External password spray against VPN gateway", status: "contained", severity: "high", updated_at: hoursAgo(3), assignee: "analyst@acme.com" },
  { id: "a1b2c3d4-0005", type: "alert", title: "Outbound DNS tunneling to suspicious TLD", status: "open", severity: "high", updated_at: hoursAgo(5), assignee: null },
  { id: "a1b2c3d4-0006", type: "alert", title: "Impossible travel — same account logged in from 2 continents", status: "open", severity: "high", updated_at: hoursAgo(7), assignee: null },
];

// ── MITRE ATT&CK matrix (subset — key tactics) ────────────────────────────

export const mockMitreMatrix: MitreTactic[] = [
  {
    id: "TA0001",
    name: "Initial Access",
    techniques: [
      { id: "T1078", name: "Valid Accounts", tactic: "Initial Access", tactic_id: "TA0001", description: "Use compromised credentials to access systems.", sub_techniques: [], covered: true, alert_count: 4 },
      { id: "T1566", name: "Phishing", tactic: "Initial Access", tactic_id: "TA0001", description: "Send phishing messages to gain access.", sub_techniques: [{ id: "T1566.001", name: "Spearphishing Attachment", description: "Targeted phishing with malicious attachments.", covered: true, alert_count: 2 }, { id: "T1566.002", name: "Spearphishing Link", description: "Targeted phishing with malicious links.", covered: false, alert_count: 0 }], covered: true, alert_count: 6 },
      { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access", tactic_id: "TA0001", description: "Exploit weaknesses in public-facing applications.", sub_techniques: [], covered: false, alert_count: 0 },
    ],
  },
  {
    id: "TA0002",
    name: "Execution",
    techniques: [
      { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution", tactic_id: "TA0002", description: "Abuse command-line interfaces to execute commands.", sub_techniques: [{ id: "T1059.001", name: "PowerShell", description: "Use PowerShell for execution.", covered: true, alert_count: 8 }, { id: "T1059.003", name: "Windows Command Shell", description: "Use cmd.exe for execution.", covered: true, alert_count: 3 }], covered: true, alert_count: 11 },
      { id: "T1053", name: "Scheduled Task/Job", tactic: "Execution", tactic_id: "TA0002", description: "Abuse task scheduling to execute malicious code.", sub_techniques: [], covered: true, alert_count: 2 },
    ],
  },
  {
    id: "TA0004",
    name: "Privilege Escalation",
    techniques: [
      { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation", tactic_id: "TA0004", description: "Circumvent privilege protections to gain elevated permissions.", sub_techniques: [], covered: true, alert_count: 3 },
      { id: "T1134", name: "Access Token Manipulation", tactic: "Privilege Escalation", tactic_id: "TA0004", description: "Manipulate tokens to escalate privileges.", sub_techniques: [], covered: false, alert_count: 0 },
    ],
  },
  {
    id: "TA0006",
    name: "Credential Access",
    techniques: [
      { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", tactic_id: "TA0006", description: "Dump credentials from OS or software.", sub_techniques: [{ id: "T1003.001", name: "LSASS Memory", description: "Read LSASS memory to dump credentials.", covered: true, alert_count: 4 }], covered: true, alert_count: 4 },
      { id: "T1110", name: "Brute Force", tactic: "Credential Access", tactic_id: "TA0006", description: "Crack or guess credentials.", sub_techniques: [{ id: "T1110.003", name: "Password Spraying", description: "Low-volume spray across many accounts.", covered: true, alert_count: 5 }], covered: true, alert_count: 5 },
    ],
  },
  {
    id: "TA0008",
    name: "Lateral Movement",
    techniques: [
      { id: "T1021", name: "Remote Services", tactic: "Lateral Movement", tactic_id: "TA0008", description: "Use remote services to move laterally.", sub_techniques: [{ id: "T1021.002", name: "SMB/Windows Admin Shares", description: "Use SMB admin shares for lateral movement.", covered: true, alert_count: 7 }], covered: true, alert_count: 7 },
      { id: "T1550", name: "Use Alternate Authentication Material", tactic: "Lateral Movement", tactic_id: "TA0008", description: "Use stolen credentials or tokens for lateral movement.", sub_techniques: [], covered: false, alert_count: 0 },
    ],
  },
  {
    id: "TA0010",
    name: "Exfiltration",
    techniques: [
      { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration", tactic_id: "TA0010", description: "Exfiltrate data over non-standard protocols.", sub_techniques: [{ id: "T1048.003", name: "Exfiltration Over Unencrypted Protocol", description: "Use unencrypted channel like DNS for exfil.", covered: true, alert_count: 2 }], covered: true, alert_count: 2 },
    ],
  },
];
