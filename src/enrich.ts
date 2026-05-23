import type {
  EnrichOptions,
  EnrichResult,
  Indicator,
  IocEnrichment,
  ProviderAdapter,
  ProviderResult,
} from './types.js';
import { compositeScore, confidenceFromCount, mergeTags } from './scoring.js';

/**
 * Indicator-type priority for the maxIndicators cap. When the caller passes
 * more indicators than `maxIndicators`, we keep the highest-priority types
 * (file hashes are the most actionable; emails the least). Customise via
 * the `typePriority` option on `enrich()`.
 */
const DEFAULT_TYPE_PRIORITY: Record<string, number> = {
  hash: 6,
  url: 5,
  domain: 4,
  ipv4: 3,
  ipv6: 2,
  email: 1,
  unknown: 0,
};

/**
 * Enrich a batch of indicators against a configured set of providers.
 *
 * The runner:
 *   1. Sorts indicators by `typePriority` (hash > url > domain > ip > email).
 *   2. Drops anything past `maxIndicators` into `overflow`.
 *   3. For each remaining indicator, fans out to every provider in parallel
 *      with a per-request timeout and bounded total concurrency.
 *   4. Per provider, `unsupported` and `error` results are excluded from the
 *      composite but preserved in the raw return.
 *   5. Returns `IocEnrichment[]` carrying the composite verdict, contributing
 *      providers, and per-provider score rows.
 *
 * Cancellation: pass `opts.signal`. All in-flight provider calls receive a
 * linked AbortSignal and the runner exits as soon as the first abort fires.
 */
export async function enrich<Env = Record<string, unknown>>(
  indicators: Indicator[],
  providers: ProviderAdapter<Env>[],
  env: Env,
  opts: EnrichOptions & { typePriority?: Record<string, number> } = {}
): Promise<EnrichResult> {
  const maxIndicators = opts.maxIndicators ?? 60;
  const concurrency = opts.concurrency ?? 8;
  const providerTimeoutMs = opts.providerTimeoutMs ?? 8000;
  const typePriority = opts.typePriority ?? DEFAULT_TYPE_PRIORITY;

  const sorted = [...indicators].sort(
    (a, b) => (typePriority[b.type] ?? 0) - (typePriority[a.type] ?? 0)
  );
  const kept = sorted.slice(0, maxIndicators);
  const overflow = sorted.slice(maxIndicators);

  const tasks = kept.flatMap((indicator) =>
    providers.map((provider) => ({ indicator, provider }))
  );

  const enrichmentMap = new Map<string, ProviderResult[]>();
  const key = (i: Indicator) => `${i.type}|${i.value}`;
  for (const i of kept) enrichmentMap.set(key(i), []);

  let active = 0;
  let nextIdx = 0;
  await new Promise<void>((resolve, reject) => {
    if (opts.signal?.aborted) return reject(new Error('aborted'));
    const onAbort = () => reject(new Error('aborted'));
    opts.signal?.addEventListener('abort', onAbort);

    const pump = () => {
      if (opts.signal?.aborted) return;
      while (active < concurrency && nextIdx < tasks.length) {
        const task = tasks[nextIdx++]!;
        active++;
        runTask(task.indicator, task.provider, env, providerTimeoutMs, opts.signal)
          .then((result) => {
            enrichmentMap.get(key(task.indicator))?.push(result);
          })
          .catch(() => {
            /* the runTask never rejects — it converts errors to result rows */
          })
          .finally(() => {
            active--;
            if (active === 0 && nextIdx >= tasks.length) {
              opts.signal?.removeEventListener('abort', onAbort);
              resolve();
            } else {
              pump();
            }
          });
      }
      if (tasks.length === 0) resolve();
    };
    pump();
  });

  const enrichments: IocEnrichment[] = kept.map((indicator): IocEnrichment => {
    const results = enrichmentMap.get(key(indicator)) ?? [];
    const composite = compositeScore(results);
    return {
      type: indicator.type,
      value: indicator.value,
      riskScore: composite.score,
      confidence: confidenceFromCount(composite.contributing),
      tags: mergeTags(results),
      listedIn: results.filter((r) => r.status === 'ok').map((r) => r.source),
      verdict: composite.verdict,
      contributing: composite.contributing,
      providerScores: composite.providerScores,
    };
  });

  return { enrichments, overflow, partial: overflow.length > 0 };
}

async function runTask<Env>(
  indicator: Indicator,
  provider: ProviderAdapter<Env>,
  env: Env,
  timeoutMs: number,
  parentSignal: AbortSignal | undefined
): Promise<ProviderResult> {
  const ctrl = new AbortController();
  const onParentAbort = () => ctrl.abort();
  parentSignal?.addEventListener('abort', onParentAbort);
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);

  try {
    return await provider(indicator, env, ctrl.signal);
  } catch (err) {
    return {
      source: 'unknown',
      status: 'error',
      score: 0,
      verdict: 'unknown',
      raw_summary: {},
      tags: [],
      error: err instanceof Error ? err.message : String(err),
      fetched_at: new Date().toISOString(),
      cached: false,
    };
  } finally {
    clearTimeout(timer);
    parentSignal?.removeEventListener('abort', onParentAbort);
  }
}
