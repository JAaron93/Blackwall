/**
 * Executable checks for scripts/jev_questions_export.mjs (Node only, not pytest).
 *
 *   node --test scripts/jev_questions_export.test.mjs
 *
 * The Python unit suite must not execute ambient host binaries; it checks the
 * shared wording statically. This file runs only under Node's built-in runner.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { ATOMIC_QUESTIONS, buildAtomicRequestBody } from './jev_questions_export.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const source = JSON.parse(
  readFileSync(join(here, '..', 'src', 'blackwall', 'policy', 'jev_questions.json'), 'utf8'),
);

test('exported questions are the shared source of truth', () => {
  assert.deepEqual(ATOMIC_QUESTIONS, source);
});

test('atomic request body keeps the egress allowlist', () => {
  const body = buildAtomicRequestBody({ model: 'jev-latest', state: { tool: { name: 'query_db' } } });
  assert.deepEqual(Object.keys(body).sort(), ['model', 'questions', 'state']);
  assert.deepEqual(body.questions, ATOMIC_QUESTIONS);
  assert.deepEqual(body.state, { tool: { name: 'query_db' } });
});

test('every question is a noul with true/false criteria', () => {
  assert.equal(Object.keys(ATOMIC_QUESTIONS).length, 6);
  for (const question of Object.values(ATOMIC_QUESTIONS)) {
    assert.equal(question.type, 'noul');
    assert.ok(question.instructions.length > 0);
    assert.ok(question.criteria.true.length > 0);
    assert.ok(question.criteria.false.length > 0);
  }
});
