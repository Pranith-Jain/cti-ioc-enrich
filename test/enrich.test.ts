import { describe, it, expect } from 'vitest';
import { enrich } from '../src/enrich.js';
import { compositeScore } from '../src/scoring.js';
import type { Indicator, ProviderAdapter, ProviderResult } from '../src/types.js';

const now = () => new Date().toISOString();

const ok = (source: string, score: number, tags: string[] = []): ProviderResult => ({
  source,
  status: 'ok',
  score,
  verdict: score >= 70 ? 'malicious' : score >= 40 ? 'suspicious' : score >= 1 ? 'clean' : 'unknown',
  raw_summary: {},
  tags,
  fetched_at: now(),
  cached: false,
});

const unsupported = (source: string): ProviderResult => ({
  source,
  status: 'unsupported',
  score: 0,
  verdict: 'unknown',
  raw_summary: {},
  tags: [],
  fetched_at: now(),
  cached: false,
});

const error = (source: string, msg: string): ProviderResult => ({
  source,
  status: 'error',
  score: 0,
  verdict: 'unknown',
  raw_summary: {},
  tags: [],
  error: msg,
  fetched_at: now(),
  cached: false,
});

// Build a provider that always returns the same result regardless of indicator.
const constProvider = (source: string, result: ProviderResult): ProviderAdapter =>
  async () => ({ ...result, source });

const slowProvider = (source: string, ms: number, result: ProviderResult): ProviderAdapter =>
  async (_ind, _env, signal) =>
    new Promise((resolve, reject) => {
      const t = setTimeout(() => resolve({ ...result, source }), ms);
      signal.addEventListener('abort', () => {
        clearTimeout(t);
        reject(new Error('aborted'));
      });
    });

const fixtureIocs = (n: number): Indicator[] =>
  Array.from({ length: n }, (_, i) => ({
    type: (['hash', 'url', 'domain', 'ipv4', 'email'] as const)[i % 5],
    value: `value-${i}`,
  }));

describe('compositeScore', () => {
  it('takes the max of contributing providers (malicious-biased)', () => {
    const r = compositeScore([ok('a', 30), ok('b', 80), ok('c', 10)]);
    expect(r.score).toBe(80);
    expect(r.verdict).toBe('malicious');
    expect(r.contributing).toBe(3);
  });

  it('excludes error and unsupported from the composite', () => {
    const r = compositeScore([ok('a', 50), error('b', 'timeout'), unsupported('c')]);
    expect(r.score).toBe(50);
    expect(r.contributing).toBe(1);
    expect(r.providerScores).toHaveLength(1);
    expect(r.providerScores[0]!.source).toBe('a');
  });

  it('returns unknown verdict when no providers responded', () => {
    const r = compositeScore([error('a', 'down'), unsupported('b')]);
    expect(r.verdict).toBe('unknown');
    expect(r.score).toBe(0);
    expect(r.contributing).toBe(0);
  });

  it('verdict mapping covers all thresholds', () => {
    expect(compositeScore([ok('a', 90)]).verdict).toBe('malicious');
    expect(compositeScore([ok('a', 50)]).verdict).toBe('suspicious');
    expect(compositeScore([ok('a', 10)]).verdict).toBe('clean');
    expect(compositeScore([ok('a', 0)]).verdict).toBe('unknown');
  });
});

describe('enrich (framework)', () => {
  it('runs providers in parallel and aggregates per-IoC', async () => {
    const providers: ProviderAdapter[] = [
      constProvider('a', ok('a', 50, ['phishing'])),
      constProvider('b', ok('b', 80, ['malware'])),
    ];
    const iocs: Indicator[] = [{ type: 'domain', value: 'evil.example' }];
    const r = await enrich(iocs, providers, {});
    expect(r.enrichments).toHaveLength(1);
    const e = r.enrichments[0]!;
    expect(e.verdict).toBe('malicious');
    expect(e.riskScore).toBe(80);
    expect(e.listedIn).toEqual(expect.arrayContaining(['a', 'b']));
    expect(e.tags).toEqual(expect.arrayContaining(['phishing', 'malware']));
    expect(e.providerScores).toHaveLength(2);
  });

  it('caps indicators at maxIndicators with the rest in overflow', async () => {
    const providers: ProviderAdapter[] = [constProvider('a', ok('a', 10))];
    const r = await enrich(fixtureIocs(20), providers, {}, { maxIndicators: 5 });
    expect(r.enrichments).toHaveLength(5);
    expect(r.overflow).toHaveLength(15);
    expect(r.partial).toBe(true);
  });

  it('prioritises higher-priority indicator types when capping', async () => {
    const providers: ProviderAdapter[] = [constProvider('a', ok('a', 10))];
    const iocs: Indicator[] = [
      { type: 'email', value: 'a@b.test' },
      { type: 'ipv4', value: '1.2.3.4' },
      { type: 'hash', value: '0'.repeat(64) },
    ];
    const r = await enrich(iocs, providers, {}, { maxIndicators: 1 });
    expect(r.enrichments).toHaveLength(1);
    expect(r.enrichments[0]!.type).toBe('hash');
    expect(r.overflow).toHaveLength(2);
  });

  it('treats `unsupported` provider results as excluded — no contributing row', async () => {
    const providers: ProviderAdapter[] = [
      constProvider('a', unsupported('a')),
      constProvider('b', ok('b', 30, ['scanner'])),
    ];
    const r = await enrich([{ type: 'ipv4', value: '1.2.3.4' }], providers, {});
    expect(r.enrichments[0]!.contributing).toBe(1);
    expect(r.enrichments[0]!.listedIn).toEqual(['b']);
  });

  it('treats provider errors as non-contributing', async () => {
    const providers: ProviderAdapter[] = [
      constProvider('a', error('a', 'network')),
      constProvider('b', ok('b', 60, [])),
    ];
    const r = await enrich([{ type: 'url', value: 'https://x.test' }], providers, {});
    expect(r.enrichments[0]!.contributing).toBe(1);
    expect(r.enrichments[0]!.riskScore).toBe(60);
  });

  it('honours per-provider timeout — slow providers fall back to error rows', async () => {
    const providers: ProviderAdapter[] = [
      slowProvider('slow', 200, ok('slow', 100)),
      constProvider('fast', ok('fast', 10)),
    ];
    const r = await enrich(
      [{ type: 'domain', value: 'x.test' }],
      providers,
      {},
      { providerTimeoutMs: 50 }
    );
    expect(r.enrichments[0]!.contributing).toBe(1);
    expect(r.enrichments[0]!.listedIn).toEqual(['fast']);
  });

  it('respects an AbortSignal — cancels in-flight tasks', async () => {
    const providers: ProviderAdapter[] = [slowProvider('slow', 500, ok('slow', 100))];
    const ctrl = new AbortController();
    const promise = enrich(
      [{ type: 'domain', value: 'x.test' }],
      providers,
      {},
      { signal: ctrl.signal }
    );
    setTimeout(() => ctrl.abort(), 20);
    await expect(promise).rejects.toThrow(/aborted/);
  });

  it('handles zero providers cleanly — empty enrichments with no errors', async () => {
    const r = await enrich([{ type: 'domain', value: 'x.test' }], [], {});
    expect(r.enrichments).toHaveLength(1);
    expect(r.enrichments[0]!.contributing).toBe(0);
    expect(r.enrichments[0]!.verdict).toBe('unknown');
  });
});
