// SPDX-License-Identifier: MIT
/**
 * Model & system version comparison harness: accuracy, latency percentiles,
 * threshold calibration, and automated promotion decisions.
 */

export interface ModelInferenceResult {
  id: string;
  groundTruth: boolean;
  confidenceScore: number;
  latencyMs: number;
  memoryMb?: number;
}

export interface ModelVersionMetrics {
  version: string;
  sampleCount: number;
  precision: number;
  recall: number;
  f1Score: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  threshold: number;
}

export interface HarnessComparisonResult {
  baseline: ModelVersionMetrics;
  candidate: ModelVersionMetrics;
  precisionDelta: number;
  recallDelta: number;
  p95LatencyDeltaMs: number;
  recommendedPromotion: boolean;
  reason: string;
}

export function computePercentile(values: number[], percentile: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.ceil((percentile / 100) * sorted.length) - 1;
  const clamped = Math.max(0, Math.min(sorted.length - 1, index));
  return Math.round(sorted[clamped] * 100) / 100;
}

export function evaluateModelVersion(
  version: string,
  results: ModelInferenceResult[],
  threshold: number = 0.5
): ModelVersionMetrics {
  if (results.length === 0) {
    return {
      version,
      sampleCount: 0,
      precision: 0,
      recall: 0,
      f1Score: 0,
      p50LatencyMs: 0,
      p95LatencyMs: 0,
      p99LatencyMs: 0,
      threshold,
    };
  }

  let tp = 0;
  let fp = 0;
  let fn = 0;
  const latencies: number[] = [];

  for (const item of results) {
    latencies.push(item.latencyMs);
    const predictedPositive = item.confidenceScore >= threshold;
    if (predictedPositive && item.groundTruth) tp++;
    else if (predictedPositive && !item.groundTruth) fp++;
    else if (!predictedPositive && item.groundTruth) fn++;
  }

  const precision = tp + fp > 0 ? Math.round((tp / (tp + fp)) * 1000) / 1000 : 0;
  const recall = tp + fn > 0 ? Math.round((tp / (tp + fn)) * 1000) / 1000 : 0;
  const f1Score = precision + recall > 0 ? Math.round(((2 * precision * recall) / (precision + recall)) * 1000) / 1000 : 0;

  return {
    version,
    sampleCount: results.length,
    precision,
    recall,
    f1Score,
    p50LatencyMs: computePercentile(latencies, 50),
    p95LatencyMs: computePercentile(latencies, 95),
    p99LatencyMs: computePercentile(latencies, 99),
    threshold,
  };
}

export function calibrateOptimalThreshold(
  results: ModelInferenceResult[],
  minTargetPrecision: number = 0.90
): number {
  if (results.length === 0) return 0.5;

  let optimalThreshold = 0.5;
  let bestF1 = -1;

  for (let t = 0.1; t <= 0.95; t += 0.05) {
    const roundedT = Math.round(t * 100) / 100;
    const m = evaluateModelVersion("test", results, roundedT);
    if (m.precision >= minTargetPrecision && m.f1Score > bestF1) {
      bestF1 = m.f1Score;
      optimalThreshold = roundedT;
    }
  }

  return optimalThreshold;
}

export function compareModelVersions(
  baseline: ModelVersionMetrics,
  candidate: ModelVersionMetrics,
  maxP95LatencyBudgetMs: number = 50.0
): HarnessComparisonResult {
  const precisionDelta = Math.round((candidate.precision - baseline.precision) * 1000) / 1000;
  const recallDelta = Math.round((candidate.recall - baseline.recall) * 1000) / 1000;
  const p95LatencyDeltaMs = Math.round((candidate.p95LatencyMs - baseline.p95LatencyMs) * 100) / 100;

  const precisionNonDegrading = candidate.precision >= baseline.precision - 0.02;
  const f1Improving = candidate.f1Score >= baseline.f1Score;
  const latencyWithinBudget = candidate.p95LatencyMs <= maxP95LatencyBudgetMs;

  const recommendedPromotion = precisionNonDegrading && f1Improving && latencyWithinBudget;

  let reason = "Candidate passes accuracy standards and latency SLA";
  if (!latencyWithinBudget) {
    reason = `Candidate p95 latency (${candidate.p95LatencyMs}ms) exceeds budget of ${maxP95LatencyBudgetMs}ms`;
  } else if (!precisionNonDegrading) {
    reason = `Candidate precision dropped by ${Math.abs(precisionDelta)}`;
  } else if (!f1Improving) {
    reason = `Candidate F1-score (${candidate.f1Score}) lower than baseline (${baseline.f1Score})`;
  }

  return {
    baseline,
    candidate,
    precisionDelta,
    recallDelta,
    p95LatencyDeltaMs,
    recommendedPromotion,
    reason,
  };
}
