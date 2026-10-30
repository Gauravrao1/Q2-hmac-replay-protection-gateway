// Q2 - Cryptographic replay test: POST -> extract header ID/challenge -> PUT with dynamic HMAC-SHA512 -> replay within 150ms.
// Node 18+ (global fetch). Run: BASE_URL=http://localhost:4010 node q2-replay-test.js
// Exit code 0 = gateway behaved securely; 1 = failure / vulnerability found.

const crypto = require('crypto');

const BASE = process.env.BASE_URL || 'http://localhost:4010';
const SHARED_SECRET = 'frugal-demo-shared-secret';
const SALT = 'frugal-salt-seq-7f3a';
const REPLAY_BUDGET_MS = 150;

const log = (lvl, msg) => console.log(`[${new Date().toISOString()}] [${lvl}] ${msg}`);
let failures = 0;
const assert = (cond, okMsg, failMsg) => {
  if (cond) log('PASS', okMsg);
  else { failures++; log('FAIL', failMsg); }
};

// Localized microsecond timestamp (ms wall clock + sub-ms from hrtime so values are unique and monotonic)
function microTimestamp() {
  const ms = BigInt(Date.now());
  const sub = (process.hrtime.bigint() / 1000n) % 1000n;
  return (ms * 1000n + sub).toString();
}

function buildMac(rawBody, tsMicros, challenge) {
  return crypto.createHmac('sha512', SHARED_SECRET)
    .update(`${rawBody}.${tsMicros}.${challenge}.${SALT}`)
    .digest('hex');
}

async function put(id, rawBody, headers) {
  return fetch(`${BASE}/transactions/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: rawBody,
  });
}

(async () => {
  // ---- Step 1: Dynamic sequence chaining ----
  const created = await fetch(`${BASE}/transactions`, { method: 'POST', body: '{}' });
  const txnId = created.headers.get('x-transaction-id');
  const challenge = created.headers.get('x-challenge-token');
  const serverTs = created.headers.get('x-server-timestamp');
  assert(created.status === 201 && txnId && challenge,
    `POST created ${txnId} (challenge ${challenge.slice(0, 8)}…, server ts ${serverTs})`,
    'POST did not return transaction ID / challenge headers');

  // ---- Step 2: PUT with dynamic X-Frugal-Mac ----
  const rawBody = JSON.stringify({ amount: 2499.5, currency: 'INR', note: 'frugal-test' });
  const ts = microTimestamp();
  const mac = buildMac(rawBody, ts, challenge);
  const headers = { 'X-Frugal-Mac': mac, 'X-Frugal-Timestamp': ts, 'X-Challenge-Token': challenge };

  const first = await put(txnId, rawBody, headers);
  const tFirstDone = performance.now();
  assert(first.status === 200, `First PUT accepted (HTTP ${first.status})`, `First PUT rejected with HTTP ${first.status}`);

  // ---- Step 3: Replay attack within 150 ms of PUT completion, identical payload/timestamp/MAC ----
  const elapsedBeforeReplay = performance.now() - tFirstDone;
  const replay = await put(txnId, rawBody, headers);
  const replayStartedAfter = elapsedBeforeReplay;
  assert(replayStartedAfter <= REPLAY_BUDGET_MS,
    `Replay fired ${replayStartedAfter.toFixed(2)} ms after first PUT completed (budget ${REPLAY_BUDGET_MS} ms)`,
    `Replay missed the ${REPLAY_BUDGET_MS} ms budget (${replayStartedAfter.toFixed(2)} ms)`);

  // ---- Step 4: Assertion layer ----
  if ([200, 201].includes(replay.status)) {
    failures++;
    log('CRITICAL', `HIGH-RISK DATA-MUTATION VULNERABILITY: replayed packet accepted with HTTP ${replay.status} (duplicate success). Replay protection missing on ${BASE}`);
  } else {
    assert([409, 422].includes(replay.status),
      `Replay correctly rejected with HTTP ${replay.status}`,
      `Replay got unexpected HTTP ${replay.status}`);
  }

  // ---- Extra negative checks (shows security understanding) ----
  const c2 = await fetch(`${BASE}/transactions`, { method: 'POST', body: '{}' });
  const id2 = c2.headers.get('x-transaction-id'), ch2 = c2.headers.get('x-challenge-token');
  const ts2 = microTimestamp();
  const body2 = JSON.stringify({ amount: 10 });
  const mac2 = buildMac(body2, ts2, ch2);
  const tampered = await put(id2, JSON.stringify({ amount: 999999 }),
    { 'X-Frugal-Mac': mac2, 'X-Frugal-Timestamp': ts2, 'X-Challenge-Token': ch2 });
  assert(tampered.status === 401, 'Tampered body rejected (401)', `Tampered body got HTTP ${tampered.status}`);

  const stale = await put(id2, body2,
    { 'X-Frugal-Mac': buildMac(body2, '1000', ch2), 'X-Frugal-Timestamp': '1000', 'X-Challenge-Token': ch2 });
  assert(stale.status === 401, 'Stale timestamp rejected (401)', `Stale timestamp got HTTP ${stale.status}`);

  log('SUMMARY', failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(2); });
