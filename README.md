# cti-ioc-enrich

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Pluggable IoC enrichment framework. You bring the provider adapters; this package gives you bounded concurrency, per-provider timeouts, AbortSignal propagation, and a composite verdict + per-provider score row for free.

Originally extracted from the threat-intel platform at [pranithjain.com](https://pranithjain.com), which runs ~20 provider adapters (VirusTotal, AbuseIPDB, Shodan, OTX, URLhaus, ThreatFox, MalwareBazaar, Tor exit list, Spamhaus DNSBL, …) against this same framework.

## Install

```bash
npm install cti-ioc-enrich
```

## Quick start

```ts
import { enrich, type ProviderAdapter, type Indicator } from 'cti-ioc-enrich';

// Define your own provider adapter. Anything matching ProviderAdapter works.
const virustotal: ProviderAdapter<{ VT_API_KEY?: string }> = async (indicator, env, signal) => {
  if (!env.VT_API_KEY) {
    return {
      source: 'virustotal',
      status: 'unsupported', // skips the request; not 'error' — keeps composite clean
      score: 0,
      verdict: 'unknown',
      raw_summary: {},
      tags: [],
      fetched_at: new Date().toISOString(),
      cached: false,
    };
  }
  const r = await fetch(`https://www.virustotal.com/api/v3/...`, {
    headers: { 'x-apikey': env.VT_API_KEY },
    signal,
  });
  // map to ProviderResult shape ...
};

const iocs: Indicator[] = [
  { type: 'ipv4', value: '203.0.113.42' },
  { type: 'domain', value: 'evil.example' },
  { type: 'hash', value: '5d41402abc4b2a76b9719d911017c592' },
];

const { enrichments, overflow, partial } = await enrich(
  iocs,
  [virustotal, /* abuseipdb, shodan, ... */],
  { VT_API_KEY: process.env.VT_API_KEY },
  { maxIndicators: 60, concurrency: 8, providerTimeoutMs: 8000 }
);
```

Each entry in `enrichments` carries:

```ts
{
  type: 'ipv4',
  value: '203.0.113.42',
  riskScore: 80,                         // composite 0-100, malicious-biased
  confidence: 75,                        // 0-100, logarithmic in # of responding providers
  tags: ['c2', 'cobalt-strike'],         // merged, deduped, sorted
  listedIn: ['threatfox', 'virustotal'], // ok-status providers
  verdict: 'malicious',
  contributing: 2,                       // providers that returned ok
  providerScores: [                      // per-provider provenance, sorted by score desc
    { source: 'threatfox', score: 90, verdict: 'malicious', tags: ['c2'] },
    { source: 'virustotal', score: 80, verdict: 'malicious', tags: ['cobalt-strike'] },
  ],
}
```

## The `ProviderAdapter` contract

```ts
type ProviderAdapter<Env> = (
  indicator: Indicator,
  env: Env,
  signal: AbortSignal
) => Promise<ProviderResult>;
```

Each adapter is responsible for:

1. **Returning `status: 'unsupported'` cleanly** when its API key is missing OR when the indicator type isn't applicable. Don't fire a request that will 401. The composite excludes `unsupported` rows, so they cost nothing.
2. **Honouring the AbortSignal.** The framework cancels slow providers via the per-provider timeout AND propagates a parent abort. Use `signal` in your `fetch()` call.
3. **Returning a typed `ProviderResult`.** See [`src/types.ts`](src/types.ts) for the full shape.

Only `ok` results contribute to the composite score. `error` and `unsupported` are preserved in the raw response but excluded from `riskScore`/`verdict`/`listedIn`.

## What the framework gives you

- **Bounded concurrency** — `concurrency: 8` default. Slow providers don't open hundreds of sockets.
- **Per-provider timeout** — `providerTimeoutMs: 8000` default. Slow providers get aborted; the rest of the run continues.
- **AbortSignal propagation** — pass `opts.signal` and every in-flight provider call gets cancelled when it fires.
- **Composite verdict** — malicious-biased (max score across `ok` providers, not average). See `compositeScore()` for the rationale.
- **Per-provider provenance** — `providerScores[]` for analyst-visible "why?" detail without re-running anything.
- **Bounded indicators** — `maxIndicators: 60` default. Overflow goes to `result.overflow`.
- **Type-priority capping** — when capping, keeps high-actionability types first (hash > url > domain > ip > email). Customise via `opts.typePriority`.

## Composite scoring details

`compositeScore()` is exported standalone for reuse:

```ts
import { compositeScore } from 'cti-ioc-enrich';

const { score, verdict, contributing, providerScores } = compositeScore(results);
```

Score = `Math.max(...okResults.map(r => r.score))`. Verdict thresholds: ≥70 malicious, ≥40 suspicious, ≥1 clean, 0 unknown.

The malicious-biased weighting is deliberate: one source seeing the activity is stronger evidence than many sources not seeing it. Most analysts expect this; naïve averaging causes "two clean providers cancel one malicious provider" failures that the bias avoids.

## What it deliberately does not do

- **No bundled provider adapters.** This is the framework. The portfolio that this is extracted from runs ~20 adapters against this same framework — see the source there for reference implementations of VirusTotal, AbuseIPDB, Shodan, OTX, URLhaus, ThreatFox, MalwareBazaar, etc.
- **No caching layer.** Adapters that want to cache should call their own KV / Redis / in-memory cache. The framework's per-call latency is wholly determined by the slowest provider.
- **No persistence.** Pure transform — call site decides where to store enrichments.
- **No type detection.** Caller passes typed `Indicator` objects. Use the bundled `detectType()` helper if you have raw strings.

## Testing

```bash
npm test
```

12 vitest cases cover the framework: composite scoring math, malicious-bias correctness, error / unsupported exclusion, indicator capping, type-priority sorting, per-provider timeout, AbortSignal propagation, zero-provider edge case.

## License

MIT — see [LICENSE](LICENSE).
