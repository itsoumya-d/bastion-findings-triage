import { describe, expect, it } from "vitest";
import {
  buildPortfolio,
  dedupeFindings,
  dueDate,
  formatRisk,
  parseVector,
  riskScore,
  scoreCvss,
  scoreFinding,
  severityFor,
  slaDays,
  slaStatus,
  type Finding,
} from "../src/findings";
import { findings } from "../src/seed";

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  id: "F-1",
  asset: "edge-api-01",
  title: "Remote code execution",
  vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  discovered: "2026-10-20",
  criticality: 5,
  exposure: "internet",
  ...overrides,
});

describe("Bastion findings triage", () => {
  it("scores a critical RCE vector at 9.8", () => {
    expect(scoreCvss("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").baseScore).toBe(9.8);
  });

  it("scores an authenticated RCE at 8.8", () => {
    expect(scoreCvss("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H").baseScore).toBe(8.8);
  });

  it("scores local privilege escalation at 7.8", () => {
    expect(scoreCvss("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H").baseScore).toBe(7.8);
  });

  it("scores a stored XSS at 6.1", () => {
    expect(scoreCvss("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").baseScore).toBe(6.1);
  });

  it("scores a TLS weakness at 5.9", () => {
    expect(scoreCvss("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N").baseScore).toBe(5.9);
  });

  it("scores no impact at zero", () => {
    expect(scoreCvss("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").baseScore).toBe(0);
  });

  it("maps critical severity", () => {
    expect(severityFor(9.8)).toBe("critical");
  });

  it("maps high severity", () => {
    expect(severityFor(7.8)).toBe("high");
  });

  it("maps medium severity", () => {
    expect(severityFor(6.1)).toBe("medium");
  });

  it("maps low severity", () => {
    expect(severityFor(3.9)).toBe("low");
  });

  it("maps none severity", () => {
    expect(severityFor(0)).toBe("none");
  });

  it("parses a CVSS vector", () => {
    const metrics = parseVector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(metrics).toMatchObject({ AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H" });
  });

  it("rejects a missing metric", () => {
    expect(() => parseVector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")).toThrow(/missing/);
  });

  it("rejects an invalid metric", () => {
    expect(() => parseVector("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toThrow(/invalid/);
  });

  it("caps risk at 100", () => {
    expect(riskScore(9.8, 5, "internet")).toBe(100);
  });

  it("weights risk by criticality and exposure", () => {
    expect(riskScore(5, 3, "internal")).toBe(30);
  });

  it("rejects invalid criticality", () => {
    expect(() => riskScore(5, 6, "internal")).toThrow(/criticality/);
  });

  it("assigns severity-based SLA days", () => {
    expect(slaDays("critical")).toBe(7);
    expect(slaDays("high")).toBe(14);
    expect(slaDays("medium")).toBe(30);
    expect(slaDays("low")).toBe(90);
  });

  it("calculates a critical due date", () => {
    expect(dueDate("2026-10-20", "critical")).toBe("2026-10-27");
  });

  it("marks an overdue SLA", () => {
    expect(slaStatus(scoreFinding(finding()), "2026-11-06")).toBe("overdue");
  });

  it("marks a due-soon SLA", () => {
    const scored = scoreFinding(finding({ discovered: "2026-11-01", vector: "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" }));
    expect(slaStatus(scored, "2026-11-13")).toBe("due-soon");
  });

  it("marks a safe SLA", () => {
    const scored = scoreFinding(finding({ discovered: "2026-11-01" }));
    expect(slaStatus(scored, "2026-11-01")).toBe("ok");
  });

  it("deduplicates identical findings", () => {
    const result = dedupeFindings([finding(), finding({ id: "F-2" })]);
    expect(result.unique).toHaveLength(1);
    expect(result.duplicates).toBe(1);
  });

  it("keeps findings with different assets", () => {
    const result = dedupeFindings([finding(), finding({ id: "F-2", asset: "other" })]);
    expect(result.unique).toHaveLength(2);
  });

  it("builds a portfolio with severity counts", () => {
    const portfolio = buildPortfolio(findings, "2026-11-06");
    expect(portfolio.total).toBe(5);
    expect(portfolio.unique).toBe(4);
    expect(portfolio.duplicates).toBe(1);
    expect(portfolio.critical).toBe(1);
    expect(portfolio.high).toBe(1);
    expect(portfolio.medium).toBe(2);
  });

  it("builds portfolio SLA counts", () => {
    const portfolio = buildPortfolio(findings, "2026-11-06");
    expect(portfolio.overdue).toBe(1);
    expect(portfolio.dueSoon).toBe(0);
  });

  it("calculates average risk", () => {
    const portfolio = buildPortfolio(findings, "2026-11-06");
    expect(portfolio.averageRisk).toBe(66.1);
  });

  it("handles an empty portfolio", () => {
    const portfolio = buildPortfolio([], "2026-11-06");
    expect(portfolio.total).toBe(0);
    expect(portfolio.averageRisk).toBe(0);
    expect(portfolio.findings).toEqual([]);
  });

  it("formats risk", () => {
    expect(formatRisk(66.135)).toBe("66.1");
  });
});
