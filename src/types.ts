import type { IndicatorType } from './indicator.js';

export type Verdict = 'clean' | 'suspicious' | 'malicious' | 'unknown';

export interface Indicator {
  type: IndicatorType;
  value: string;
}

/**
 * Raw result returned by a single provider adapter for a single indicator.
 *
 * `status`:
 *   - `ok` — provider returned a usable answer (even if verdict is `unknown`).
 *   - `unsupported` — provider doesn't handle this indicator type, or its API
 *     key isn't configured. Return this instead of firing a request that
 *     would fail with an opaque 401.
 *   - `error` — provider was attempted but failed (timeout, network error,
 *     upstream 5xx). `error` field carries the message.
 *
 * Only `ok` results contribute to the composite score.
 */
export interface ProviderResult {
  source: string;
  status: 'ok' | 'error' | 'unsupported';
  /** 0-100, higher = more malicious. Required when status='ok'. */
  score: number;
  verdict: Verdict;
  raw_summary: Record<string, unknown>;
  tags: string[];
  error?: string;
  fetched_at: string;
  cached: boolean;
}

/**
 * A provider adapter. Anything matching this signature can be plugged into
 * the framework.
 *
 * The adapter is responsible for:
 *   - Returning `unsupported` cleanly when its API key is missing or the
 *     indicator type isn't applicable.
 *   - Honouring the AbortSignal — the runner will cancel slow providers.
 *   - Returning quickly on cache hits (caller may pass a cache via `ctx.cache`).
 */
export type ProviderAdapter<Env = Record<string, unknown>> = (
  indicator: Indicator,
  env: Env,
  signal: AbortSignal
) => Promise<ProviderResult>;

/**
 * Per-provider score row that contributes to an IoC's composite verdict.
 * Only successful (`ok`) provider runs surface here; errors and unsupported
 * are filtered upstream and excluded.
 */
export interface ProviderScore {
  source: string;
  score: number;
  verdict: Verdict;
  tags: string[];
}

/**
 * Aggregated per-IoC enrichment result. Carries the composite verdict plus
 * the per-provider rows that contributed, for analyst-visible provenance.
 */
export interface IocEnrichment {
  type: IndicatorType;
  value: string;
  /** 0-100 composite risk score, malicious-biased. */
  riskScore: number;
  /** 0-100 normalized count of contributing OK providers. */
  confidence: number;
  /** Union of provider tags, deduped + normalized. */
  tags: string[];
  /** Provider IDs that returned `ok` for this indicator. */
  listedIn: string[];
  verdict: Verdict;
  /** Providers attempted (excluded `unsupported`). */
  contributing: number;
  /** Per-provider rows, sorted by score desc. */
  providerScores: ProviderScore[];
}

export interface EnrichOptions {
  /** Hard cap on the number of indicators enriched. Excess go to `overflow`. */
  maxIndicators?: number;
  /** Maximum concurrent provider × indicator pairs in flight. */
  concurrency?: number;
  /** Per-provider request timeout in ms. */
  providerTimeoutMs?: number;
  /** Optional AbortSignal — cancels all in-flight provider calls. */
  signal?: AbortSignal;
}

export interface EnrichResult {
  enrichments: IocEnrichment[];
  /** Indicators dropped because of `maxIndicators`. */
  overflow: Indicator[];
  /** True when overflow > 0 or any indicator had < `partialThreshold` providers respond. */
  partial: boolean;
}
