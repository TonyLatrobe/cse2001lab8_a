// Exercises all three endpoints. The SHA-256 value of `"hello"` is a known constant — if the server returns the wrong hash under load, the check fails and the pipeline fails.
// Topic 10: Load and Performance Testing
// Thresholds are quality gates — breach either and k6 exits non-zero.
// Correctness check: SHA-256 of "hello" is a compile-time constant.
// If the hash changes under load something is very wrong.

import http from 'k6/http';
import { check, sleep } from 'k6';

// SHA-256("hello") — deterministic ground truth
const SHA256_HELLO = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';

// Read target URL from --env flag passed by Jenkins.
// Fallback to staging cluster DNS so the script is also runnable locally
// via: k6 run --env API_BASE_URL=http://localhost:8080 load-test/k6-script.js
const BASE = __ENV.API_BASE_URL || 'http://hash-api.staging.svc.cluster.local:8080';

export const options = {
  stages: [
    { duration: '15s', target: 5  },   // ramp up
    { duration: '30s', target: 10 },   // hold load
    { duration: '10s', target: 0  },   // ramp down
  ],
  thresholds: {
    // Quality gates — pipeline fails if either is breached
    http_req_duration: ['p(95)<200'],  // hash ops are CPU-bound, should be fast
    http_req_failed:   ['rate<0.05'],  // < 5% error rate
  },
};

export default function () {

  // ── GET /hash — sha256 ──────────────────────────────────────────────────
  const getRes = http.get(`${BASE}/hash?algorithm=sha256&data=hello`);
  check(getRes, {
    'GET /hash 200':               (r) => r.status === 200,
    'GET /hash sha256 correct':    (r) => {
      try { return JSON.parse(r.body).hash === SHA256_HELLO; }
      catch { return false; }
    },
    'GET /hash under 100ms':       (r) => r.timings.duration < 100,
  });

  // ── POST /hash ──────────────────────────────────────────────────────────
  const postRes = http.post(
    `${BASE}/hash`,
    JSON.stringify({ algorithm: 'sha256', data: 'hello' }),
    { headers: { 'Content-Type': 'application/json' } }
  );
  check(postRes, {
    'POST /hash 200':              (r) => r.status === 200,
    'POST /hash sha256 correct':   (r) => {
      try { return JSON.parse(r.body).hash === SHA256_HELLO; }
      catch { return false; }
    },
  });

  // ── GET /health ─────────────────────────────────────────────────────────
  const healthRes = http.get(`${BASE}/health`);
  check(healthRes, {
    '/health 200':                 (r) => r.status === 200,
    '/health has status field':    (r) => {
      try { return JSON.parse(r.body).status === 'ok'; }
      catch { return false; }
    },
  });

  // ── Error path — invalid algorithm (every 10th VU iteration) ───────────
  if (__ITER % 10 === 0) {
    const badRes = http.get(`${BASE}/hash?algorithm=md99&data=test`);
    check(badRes, {
      'invalid algo returns 400':  (r) => r.status === 400,
    });
  }

  sleep(1);
}