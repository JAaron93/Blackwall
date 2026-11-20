// Single source of truth for Track G wording, shared with the Python policy module.
// Node wrapper used by the parity test: prints the exact question map as JSON.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const questionsPath = join(here, '..', 'src', 'blackwall', 'policy', 'jev_questions.json');

export const ATOMIC_QUESTIONS = JSON.parse(readFileSync(questionsPath, 'utf8'));

/** Build a System One request using the bundled atomic questions over shared state. */
export function buildAtomicRequestBody({ model, state }) {
  return { model, state, questions: ATOMIC_QUESTIONS };
}

// `node scripts/jev_questions_export.mjs` is the parity-test surface.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.stdout.write(JSON.stringify(ATOMIC_QUESTIONS));
}
