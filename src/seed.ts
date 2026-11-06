import type { Finding } from "./findings.js";

export const findings: Finding[] = [
  {
    id: "F-001",
    asset: "edge-api-01",
    title: "Remote code execution in public API",
    vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    discovered: "2026-10-20",
    criticality: 5,
    exposure: "internet",
  },
  {
    id: "F-002",
    asset: "partner-portal",
    title: "Stored XSS in partner profile",
    vector: "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    discovered: "2026-10-28",
    criticality: 4,
    exposure: "partner",
  },
  {
    id: "F-003",
    asset: "edge-api-01",
    title: "Remote code execution in public API",
    vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    discovered: "2026-10-21",
    criticality: 5,
    exposure: "internet",
  },
  {
    id: "F-004",
    asset: "finance-db",
    title: "Local privilege escalation",
    vector: "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    discovered: "2026-11-01",
    criticality: 4,
    exposure: "internal",
  },
  {
    id: "F-005",
    asset: "legacy-vpn",
    title: "TLS configuration weakness",
    vector: "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    discovered: "2026-10-25",
    criticality: 3,
    exposure: "internet",
  },
];
