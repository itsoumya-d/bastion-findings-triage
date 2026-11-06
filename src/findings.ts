export type Severity = "none" | "low" | "medium" | "high" | "critical";
export type Exposure = "internet" | "partner" | "internal";

export interface CvssMetrics {
  AV: "N" | "A" | "L" | "P";
  AC: "L" | "H";
  PR: "N" | "L" | "H";
  UI: "N" | "R";
  S: "U" | "C";
  C: "H" | "L" | "N";
  I: "H" | "L" | "N";
  A: "H" | "L" | "N";
}

export interface CvssScore {
  baseScore: number;
  severity: Severity;
  metrics: CvssMetrics;
}

export interface Finding {
  id: string;
  asset: string;
  title: string;
  vector: string;
  discovered: string;
  criticality: number;
  exposure: Exposure;
}

export interface ScoredFinding extends Finding {
  cvss: CvssScore;
  riskScore: number;
  dueDate: string;
  slaDays: number;
}

export interface Portfolio {
  total: number;
  unique: number;
  duplicates: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  overdue: number;
  dueSoon: number;
  averageRisk: number;
  findings: ScoredFinding[];
}

const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as const;
const AC = { L: 0.77, H: 0.44 } as const;
const UI = { N: 0.85, R: 0.62 } as const;
const CIA = { H: 0.56, L: 0.22, N: 0 } as const;
const EXPOSURE = { internet: 1.3, partner: 1.15, internal: 1.0 } as const;
const SLA_DAYS: Record<Severity, number> = { critical: 7, high: 14, medium: 30, low: 90, none: 180 };

function roundUp(value: number): number {
  return Math.ceil(value * 10) / 10;
}

export function parseVector(vector: string): CvssMetrics {
  const values = new Map<string, string>();
  for (const part of vector.split("/")) {
    const [key, value] = part.split(":");
    if (!key || !value) continue;
    values.set(key, value);
  }
  const required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
  for (const key of required) {
    if (!values.has(key)) throw new Error(`missing CVSS metric ${key}`);
  }
  const metrics = {
    AV: values.get("AV") as CvssMetrics["AV"],
    AC: values.get("AC") as CvssMetrics["AC"],
    PR: values.get("PR") as CvssMetrics["PR"],
    UI: values.get("UI") as CvssMetrics["UI"],
    S: values.get("S") as CvssMetrics["S"],
    C: values.get("C") as CvssMetrics["C"],
    I: values.get("I") as CvssMetrics["I"],
    A: values.get("A") as CvssMetrics["A"],
  };
  if (!(metrics.AV in AV) || !(metrics.AC in AC) || !(metrics.PR in { N: 0, L: 0, H: 0 })) throw new Error("invalid CVSS AV/AC/PR");
  if (!(metrics.UI in UI) || !(metrics.S in { U: 0, C: 0 })) throw new Error("invalid CVSS UI/S");
  if (!(metrics.C in CIA) || !(metrics.I in CIA) || !(metrics.A in CIA)) throw new Error("invalid CVSS CIA");
  return metrics;
}

export function severityFor(score: number): Severity {
  if (score <= 0) return "none";
  if (score < 4) return "low";
  if (score < 7) return "medium";
  if (score < 9) return "high";
  return "critical";
}

export function scoreCvss(vector: string): CvssScore {
  const metrics = parseVector(vector);
  const prValues = metrics.S === "U"
    ? { N: 0.85, L: 0.62, H: 0.27 }
    : { N: 0.85, L: 0.68, H: 0.5 };
  const iss = 1 - ((1 - CIA[metrics.C]) * (1 - CIA[metrics.I]) * (1 - CIA[metrics.A]));
  const impact = metrics.S === "U"
    ? 6.42 * iss
    : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability = 8.22 * AV[metrics.AV] * AC[metrics.AC] * prValues[metrics.PR] * UI[metrics.UI];
  const baseScore = impact <= 0
    ? 0
    : metrics.S === "U"
      ? roundUp(Math.min(impact + exploitability, 10))
      : roundUp(Math.min(1.08 * (impact + exploitability), 10));
  return { baseScore, severity: severityFor(baseScore), metrics };
}

export function riskScore(score: number, criticality: number, exposure: Exposure): number {
  if (criticality < 1 || criticality > 5) throw new Error("criticality must be between 1 and 5");
  const value = score * (criticality / 5) * EXPOSURE[exposure] * 10;
  return Math.round(Math.min(100, value) * 10) / 10;
}

export function slaDays(severity: Severity): number {
  return SLA_DAYS[severity];
}

export function dueDate(discovered: string, severity: Severity): string {
  const date = new Date(`${discovered}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + slaDays(severity));
  return date.toISOString().slice(0, 10);
}

export function scoreFinding(finding: Finding): ScoredFinding {
  const cvss = scoreCvss(finding.vector);
  return {
    ...finding,
    cvss,
    riskScore: riskScore(cvss.baseScore, finding.criticality, finding.exposure),
    dueDate: dueDate(finding.discovered, cvss.severity),
    slaDays: slaDays(cvss.severity),
  };
}

export function slaStatus(finding: ScoredFinding, today: string): "overdue" | "due-soon" | "ok" {
  const due = new Date(`${finding.dueDate}T00:00:00Z`).getTime();
  const now = new Date(`${today}T00:00:00Z`).getTime();
  const days = Math.floor((due - now) / 86_400_000);
  if (days < 0) return "overdue";
  if (days <= 3) return "due-soon";
  return "ok";
}

export function dedupeFindings(findings: Finding[]): { unique: Finding[]; duplicates: number } {
  const seen = new Map<string, Finding>();
  let duplicates = 0;
  for (const finding of findings) {
    const key = `${finding.asset}|${finding.title}|${finding.vector}`;
    if (seen.has(key)) duplicates += 1;
    else seen.set(key, finding);
  }
  return { unique: [...seen.values()], duplicates };
}

export function buildPortfolio(findings: Finding[], today: string): Portfolio {
  const { unique, duplicates } = dedupeFindings(findings);
  const scored = unique.map(scoreFinding);
  const active = scored.filter((finding) => finding.cvss.severity !== "none");
  return {
    total: findings.length,
    unique: unique.length,
    duplicates,
    critical: active.filter((finding) => finding.cvss.severity === "critical").length,
    high: active.filter((finding) => finding.cvss.severity === "high").length,
    medium: active.filter((finding) => finding.cvss.severity === "medium").length,
    low: active.filter((finding) => finding.cvss.severity === "low").length,
    overdue: scored.filter((finding) => slaStatus(finding, today) === "overdue").length,
    dueSoon: scored.filter((finding) => slaStatus(finding, today) === "due-soon").length,
    averageRisk: active.length ? Math.round((active.reduce((sum, finding) => sum + finding.riskScore, 0) / active.length) * 10) / 10 : 0,
    findings: scored,
  };
}

export function formatRisk(value: number): string {
  return value.toFixed(1);
}
