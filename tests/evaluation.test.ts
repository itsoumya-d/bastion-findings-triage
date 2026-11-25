// SPDX-License-Identifier: MIT
import { describe, expect, it } from "vitest";
import {
  calibrateOptimalThreshold,
  compareModelVersions,
  computePercentile,
  evaluateModelVersion,
  type ModelInferenceResult,
} from "../src/evaluation";

describe("Evaluation & Comparison Harness", () => {
  const sampleData: ModelInferenceResult[] = [
    { id: "1", groundTruth: true, confidenceScore: 0.95, latencyMs: 12.4 },
    { id: "2", groundTruth: true, confidenceScore: 0.88, latencyMs: 15.1 },
    { id: "3", groundTruth: true, confidenceScore: 0.72, latencyMs: 18.2 },
    { id: "4", groundTruth: false, confidenceScore: 0.65, latencyMs: 14.0 },
    { id: "5", groundTruth: false, confidenceScore: 0.20, latencyMs: 11.5 },
    { id: "6", groundTruth: false, confidenceScore: 0.15, latencyMs: 10.8 },
  ];

  it("calculates accurate percentiles", () => {
    const latencies = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    expect(computePercentile(latencies, 50)).toBe(50);
    expect(computePercentile(latencies, 95)).toBe(100);
    expect(computePercentile([], 50)).toBe(0);
  });

  it("evaluates model version metrics correctly", () => {
    const metrics = evaluateModelVersion("v1.0.0", sampleData, 0.7);
    expect(metrics.version).toBe("v1.0.0");
    expect(metrics.sampleCount).toBe(6);
    // At threshold 0.7: predicted pos = ids 1, 2, 3 (true positives = 3, false positives = 0)
    expect(metrics.precision).toBe(1.0);
    expect(metrics.recall).toBe(1.0);
    expect(metrics.f1Score).toBe(1.0);
    expect(metrics.p50LatencyMs).toBe(12.4);
  });

  it("handles empty evaluation dataset safely", () => {
    const emptyMetrics = evaluateModelVersion("v0.0.0", [], 0.5);
    expect(emptyMetrics.sampleCount).toBe(0);
    expect(emptyMetrics.precision).toBe(0);
    expect(emptyMetrics.p95LatencyMs).toBe(0);
  });

  it("calibrates optimal threshold meeting minimum precision", () => {
    const optimal = calibrateOptimalThreshold(sampleData, 0.95);
    expect(optimal).toBeGreaterThanOrEqual(0.7);
    const m = evaluateModelVersion("test", sampleData, optimal);
    expect(m.precision).toBeGreaterThanOrEqual(0.95);
  });

  it("recommends promotion when candidate meets accuracy and latency SLAs", () => {
    const baseline = evaluateModelVersion("v1.0.0", sampleData, 0.6);
    const candidateData: ModelInferenceResult[] = [
      { id: "1", groundTruth: true, confidenceScore: 0.96, latencyMs: 9.2 },
      { id: "2", groundTruth: true, confidenceScore: 0.91, latencyMs: 10.4 },
      { id: "3", groundTruth: true, confidenceScore: 0.85, latencyMs: 11.0 },
      { id: "4", groundTruth: false, confidenceScore: 0.30, latencyMs: 8.5 },
      { id: "5", groundTruth: false, confidenceScore: 0.10, latencyMs: 9.0 },
    ];
    const candidate = evaluateModelVersion("v1.1.0", candidateData, 0.6);

    const comp = compareModelVersions(baseline, candidate, 25.0);
    expect(comp.recommendedPromotion).toBe(true);
    expect(comp.p95LatencyDeltaMs).toBeLessThan(0);
  });

  it("rejects promotion when candidate exceeds latency budget", () => {
    const baseline = evaluateModelVersion("v1.0.0", sampleData, 0.7);
    const slowCandidateData: ModelInferenceResult[] = [
      { id: "1", groundTruth: true, confidenceScore: 0.99, latencyMs: 65.0 },
      { id: "2", groundTruth: true, confidenceScore: 0.95, latencyMs: 72.0 },
    ];
    const candidate = evaluateModelVersion("v2.0.0-slow", slowCandidateData, 0.7);

    const comp = compareModelVersions(baseline, candidate, 30.0);
    expect(comp.recommendedPromotion).toBe(false);
    expect(comp.reason).toContain("exceeds budget");
  });
});
