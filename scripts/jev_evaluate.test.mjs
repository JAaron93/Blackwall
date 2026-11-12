/**
 * Contract tests for scripts/jev_evaluate.mjs (official TypeSafe AI API).
 *
 *   node --test scripts/jev_evaluate.test.mjs
 *
 * Node's built-in runner, no dependencies. Dev-tooling tests live here rather
 * than under pytest on purpose: the Python suite must not execute ambient host
 * binaries such as `node` (.agents/rules/testing_and_hygiene.md rule 61).
 * Every network call goes to a loopback server started by the test; the child
 * process gets a minimal, explicit environment so no real key can leak in.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  DEFAULT_BASE_URL,
  DEFAULT_MODEL,
  IS_THREAT_INSTRUCTIONS,
  endpointFor,
  buildRequestBody,
  parseSystemOne,
  isRetryableStatus,
  RETRY_DELAY_MS,
  reusableRows,
  resumeKey,
} from './jev_evaluate.mjs';

const HELPER = join(dirname(fileURLToPath(import.meta.url)), 'jev_evaluate.mjs');

// ---------------------------------------------------------------- pure wire

test('endpoint joins an API root (never a path) with /v1/systemone', () => {
  assert.equal(DEFAULT_BASE_URL, 'https://api.typesafe.ai');
  assert.equal(endpointFor('https://api.typesafe.ai'), 'https://api.typesafe.ai/v1/systemone');
  assert.equal(endpointFor('https://api.typesafe.ai/'), 'https://api.typesafe.ai/v1/systemone');
  assert.equal(endpointFor('http://127.0.0.1:8080//'), 'http://127.0.0.1:8080/v1/systemone');
});

test('request body is exactly model/state/questions with a noul question', () => {
  const body = buildRequestBody({ model: DEFAULT_MODEL, state: 'Tool: x', instructions: null });
  assert.deepEqual(Object.keys(body).sort(), ['model', 'questions', 'state']);
  assert.equal(DEFAULT_MODEL, 'jev-latest');
  assert.deepEqual(body.questions, {
    is_threat: { type: 'noul', instructions: IS_THREAT_INSTRUCTIONS },
  });
  assert.equal('providerOptions' in body, false);
});

test('custom instructions override the default question text only', () => {
  const body = buildRequestBody({ model: 'jev-1.13.0', state: 's', instructions: 'Is it bad?' });
  assert.equal(body.model, 'jev-1.13.0');
  assert.equal(body.questions.is_threat.type, 'noul');
  assert.equal(body.questions.is_threat.instructions, 'Is it bad?');
});

test('parse reads answers.is_threat.noul, served model and usage', () => {
  const out = parseSystemOne({
    model: 'jev-1.14.0',
    answers: { is_threat: { type: 'noul', noul: 0.42 } },
    usage: { input_tokens: 120, output_tokens: 8 },
  });
  assert.equal(out.p, 0.42);
  assert.equal(out.servedModel, 'jev-1.14.0');
  assert.deepEqual(out.usage, { input_tokens: 120, output_tokens: 8 });
});

test('parse rejects malformed, out-of-range and Vercel-era shapes', () => {
  const bad = [
    {},
    { answers: {} },
    { answers: { is_threat: { type: 'noul' } } },
    { answers: { is_threat: { type: 'noul', noul: 'high' } } },
    { answers: { is_threat: { type: 'noul', noul: true } } },
    { answers: { is_threat: { type: 'noul', noul: -0.1 } } },
    { answers: { is_threat: { type: 'noul', noul: 1.5 } } },
    { answers: { is_threat: { type: 'noul', noul: Number.NaN } } },
    { answers: { is_threat: { type: 'boolean', probability: 0.02 } } },
  ];
  for (const body of bad) assert.equal(parseSystemOne(body).p, null, JSON.stringify(body));
});

test('only 429 and 529 are retryable', () => {
  for (const s of [429, 529]) assert.equal(isRetryableStatus(s), true, String(s));
  for (const s of [200, 400, 401, 413, 422, 500, 503]) {
    assert.equal(isRetryableStatus(s), false, String(s));
  }
});

test('the retry delay is a short fixed constant (paid API, single retry)', () => {
  assert.equal(RETRY_DELAY_MS, 500);
});

test('resume reuses only error-free rows produced by the same requested model', () => {
  const rows = [
    { id: 'a', model: 'jev-latest', p: 0.1, error: null },
    { id: 'b', model: 'jev-latest', p: null, error: 'boom' },
    { id: 'c', model: 'jev-1.13.0', p: 0.2, error: null },
    { id: 'd', p: 0.9, error: null }, // pre-ADR-0008 Vercel Gateway row: no model
  ];
  assert.deepEqual(reusableRows(rows, 'jev-latest').map((r) => r.id), ['a']);
  assert.notEqual(resumeKey('a', 'h', 's', 'jev-latest'), resumeKey('a', 'h', 's', 'jev-1.13.0'));
});

// ------------------------------------------------------- CLI over loopback

/** Loopback stand-in for the TypeSafe API; replies from a scripted queue. */
async function fakeApi(script) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body: raw });
      const reply = script.length > 1 ? script.shift() : script[0];
      res.writeHead(reply.status, { 'content-type': 'application/json', ...(reply.headers ?? {}) });
      res.end(JSON.stringify(reply.json ?? {}));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  return { url, seen, close: () => new Promise((resolve) => server.close(resolve)) };
}

const ok = (p, extra = {}) => ({
  status: 200,
  json: {
    model: 'jev-1.14.0',
    answers: { is_threat: { type: 'noul', noul: p } },
    usage: { input_tokens: 100, output_tokens: 5 },
    ...extra,
  },
});

/** Run the helper with an explicit minimal env (nothing ambient). */
function runHelper(args, env, stdin = '') {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [HELPER, ...args], {
      env: { PATH: process.env.PATH, ...env },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => (stdout += c));
    child.stderr.on('data', (c) => (stderr += c));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(stdin);
  });
}

test('single: POSTs the System One contract with bearer auth and reports p', async () => {
  const api = await fakeApi([ok(0.42)]);
  try {
    const out = await runHelper(
      ['single'],
      { TYPESAFE_API_KEY: 'test-key', TYPESAFE_BASE_URL: api.url },
      JSON.stringify({ state: 'Tool: execute_bash\nRequest: ls' }),
    );
    assert.equal(out.code, 0, out.stderr);
    const result = JSON.parse(out.stdout);
    assert.equal(result.p, 0.42);
    assert.equal(result.model, 'jev-latest');
    assert.equal(result.served_model, 'jev-1.14.0');
    assert.deepEqual(result.usage, { input_tokens: 100, output_tokens: 5 });
    assert.equal(result.is_fallback, false);
    assert.equal(api.seen.length, 1);
    const req = api.seen[0];
    assert.equal(req.method, 'POST');
    assert.equal(req.url, '/v1/systemone');
    assert.equal(req.headers.authorization, 'Bearer test-key');
    const body = JSON.parse(req.body);
    assert.deepEqual(Object.keys(body).sort(), ['model', 'questions', 'state']);
    assert.equal(body.questions.is_threat.type, 'noul');
  } finally {
    await api.close();
  }
});

test('single: JEV_MODEL pins the requested model', async () => {
  const api = await fakeApi([ok(0.1)]);
  try {
    const out = await runHelper(
      ['single'],
      { TYPESAFE_API_KEY: 'k', TYPESAFE_BASE_URL: api.url, JEV_MODEL: 'jev-1.13.0' },
      JSON.stringify({ state: 's' }),
    );
    assert.equal(JSON.parse(out.stdout).model, 'jev-1.13.0');
    assert.equal(JSON.parse(api.seen[0].body).model, 'jev-1.13.0');
  } finally {
    await api.close();
  }
});

test('single: 529 then 200 is retried with backoff', async () => {
  const api = await fakeApi([{ status: 529, json: { message: 'overloaded' } }, ok(0.9)]);
  try {
    const out = await runHelper(
      ['single'],
      { TYPESAFE_API_KEY: 'k', TYPESAFE_BASE_URL: api.url },
      JSON.stringify({ state: 's' }),
    );
    assert.equal(out.code, 0, out.stderr);
    assert.equal(JSON.parse(out.stdout).p, 0.9);
    assert.equal(api.seen.length, 2);
  } finally {
    await api.close();
  }
});

test('single: throttled twice is a recorded fallback after exactly two requests', async () => {
  const api = await fakeApi([{ status: 429, json: { message: 'slow down' } }]);
  try {
    // Removed pre-ADR-0008 knobs must be inert: a stale JEV_MAX_ATTEMPTS cannot
    // turn the single retry back into a loop.
    const out = await runHelper(
      ['single'],
      { TYPESAFE_API_KEY: 'k', TYPESAFE_BASE_URL: api.url, JEV_MAX_ATTEMPTS: '9' },
      JSON.stringify({ state: 's' }),
    );
    const result = JSON.parse(out.stdout);
    assert.equal(out.code, 1);
    assert.equal(result.p, null);
    assert.equal(result.is_fallback, true);
    assert.match(result.error, /429/);
    assert.equal(api.seen.length, 2);
  } finally {
    await api.close();
  }
});

test('single: a non-retryable status is a recorded fallback, never retried', async () => {
  const api = await fakeApi([{ status: 401, json: { message: 'bad key' } }]);
  try {
    const out = await runHelper(
      ['single'],
      { TYPESAFE_API_KEY: 'k', TYPESAFE_BASE_URL: api.url },
      JSON.stringify({ state: 's' }),
    );
    const result = JSON.parse(out.stdout);
    assert.equal(out.code, 1);
    assert.equal(result.p, null);
    assert.equal(result.is_fallback, true);
    assert.match(result.error, /401/);
    assert.equal(api.seen.length, 1);
  } finally {
    await api.close();
  }
});

test('single: a malformed 200 body is a recorded fallback, not a silent null', async () => {
  const api = await fakeApi([{ status: 200, json: { answers: {} } }]);
  try {
    const out = await runHelper(
      ['single'],
      { TYPESAFE_API_KEY: 'k', TYPESAFE_BASE_URL: api.url },
      JSON.stringify({ state: 's' }),
    );
    const result = JSON.parse(out.stdout);
    assert.equal(result.p, null);
    assert.equal(result.is_fallback, true);
    assert.ok(result.error);
  } finally {
    await api.close();
  }
});

test('requires TYPESAFE_API_KEY and ignores the legacy Vercel credential', async () => {
  const out = await runHelper(['single'], { AI_GATEWAY_API_KEY: 'legacy-vercel-credential' });
  assert.equal(out.code, 2);
  assert.match(out.stderr, /TYPESAFE_API_KEY is not set/);
});

test('batch: rows without this run\'s model (Vercel-era) are never reused or kept', async () => {
  const api = await fakeApi([ok(0.2)]);
  const dir = mkdtempSync(join(tmpdir(), 'jev-eval-'));
  const casesPath = join(dir, 'cases.json');
  const outPath = join(dir, 'out.json');
  const meta = { id: 'case-1', suite: 'security', h: 'abc123', label: 0, expected: 'ALLOW', scenario: 's', tool: 't' };
  writeFileSync(casesPath, JSON.stringify([{ ...meta, state: 'Tool: t\nRequest: hi' }]));
  // Legacy Gateway row: same (id, hash, suite) but no model and a stale probability.
  writeFileSync(outPath, JSON.stringify([{ ...meta, p: 0.99, confidence: 0.9, usage: { inputTokens: 1 }, error: null }]));
  try {
    const out = await runHelper(
      ['batch', casesPath, outPath],
      { TYPESAFE_API_KEY: 'k', TYPESAFE_BASE_URL: api.url },
    );
    assert.equal(out.code, 0, out.stderr);
    assert.equal(api.seen.length, 1, 'legacy row must not satisfy resume');
    const rows = JSON.parse(readFileSync(outPath, 'utf8'));
    assert.equal(rows.length, 1, 'legacy row must not survive into the output');
    assert.equal(rows[0].p, 0.2);
    assert.equal(rows[0].model, 'jev-latest');
    assert.equal(rows[0].served_model, 'jev-1.14.0');
  } finally {
    await api.close();
  }
});

test('batch: a row from the same model is reused without any API call', async () => {
  const api = await fakeApi([ok(0.7)]);
  const dir = mkdtempSync(join(tmpdir(), 'jev-eval-'));
  const casesPath = join(dir, 'cases.json');
  const outPath = join(dir, 'out.json');
  const meta = { id: 'case-1', suite: 'security', h: 'abc123', label: 0, expected: 'ALLOW', scenario: 's', tool: 't' };
  writeFileSync(casesPath, JSON.stringify([{ ...meta, state: 'Tool: t\nRequest: hi' }]));
  writeFileSync(outPath, JSON.stringify([{ ...meta, p: 0.15, model: 'jev-latest', served_model: 'jev-1.14.0', usage: null, error: null, is_fallback: false }]));
  try {
    const out = await runHelper(
      ['batch', casesPath, outPath],
      { TYPESAFE_API_KEY: 'k', TYPESAFE_BASE_URL: api.url },
    );
    assert.equal(out.code, 0, out.stderr);
    assert.equal(api.seen.length, 0);
    assert.equal(JSON.parse(readFileSync(outPath, 'utf8'))[0].p, 0.15);
  } finally {
    await api.close();
  }
});
