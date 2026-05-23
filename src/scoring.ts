import type { ProviderResult, ProviderScore, Verdict } from './types.js';

/**
 * Compute a composite verdict + score from a set of per-provider results.
 *
 * Scoring rules:
 *   - Only `ok` results contribute. Errors and `unsupported` are skipped.
 *   - The composite score is the **max** of contributing provider scores —
 *     this is malicious-biased on purpose. A single high-confidence
 *     "malicious" verdict outweighs many "clean" ones because one source
 *     SEEING the activity is stronger evidence than many sources NOT
 *     seeing it.
 *   - Verdict mapping: ≥70 = malicious, ≥40 = suspicious, ≥1 = clean,
 *     0 = unknown.
 *
 * The malicious-biased weighting matches what most analysts expect when
 * they look at a multi-source IOC verdict. It's a deliberate departure
 * from naïve averaging.
 */
export function compositeScore(results: ProviderResult[]): {
  score: number;
  verdict: Verdict;
  contributing: number;
  providerScores: ProviderScore[];
} {
  const ok = results.filter((r) => r.status === 'ok');
  if (ok.length === 0) {
    return { score: 0, verdict: 'unknown', contributing: 0, providerScores: [] };
  }

  const score = Math.max(...ok.map((r) => r.score));
  const verdict: Verdict = score >= 70 ? 'malicious' : score >= 40 ? 'suspicious' : score >= 1 ? 'clean' : 'unknown';

  const providerScores: ProviderScore[] = ok
    .map((r) => ({
      source: r.source,
      score: r.score,
      verdict: r.verdict,
      tags: r.tags.slice(0, 8),
    }))
    .sort((a, b) => b.score - a.score);

  return { score, verdict, contributing: ok.length, providerScores };
}

/**
 * Confidence normaliser. Maps "N providers responded" → 0-100. The shape
 * is logarithmic — going from 0 → 1 provider is high signal, going from
 * 5 → 6 is small.
 */
export function confidenceFromCount(n: number): number {
  if (n === 0) return 0;
  if (n >= 6) return 100;
  return [0, 40, 60, 75, 85, 92, 100][n] ?? 100;
}

/**
 * Deduplicate + normalize tags from multiple providers. Lowercase, trim,
 * drop empties, alphabetical order.
 */
export function mergeTags(results: ProviderResult[], cap = 24): string[] {
  const seen = new Set<string>();
  for (const r of results) {
    if (r.status !== 'ok') continue;
    for (const t of r.tags) {
      const lower = t.toLowerCase().trim();
      if (lower) seen.add(lower);
    }
  }
  return [...seen].sort().slice(0, cap);
}
