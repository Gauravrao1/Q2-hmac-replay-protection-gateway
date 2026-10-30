// Q2 - Local mock payment gateway exposing: challenge nonces, HMAC-SHA512 header validation, replay protection.
// Pure Node (no dependencies). Run: node mock-server.js   (PORT=4010 default)
// Set VULNERABLE=1 to disable replay protection so the test framework's vulnerability alert can be demonstrated.

const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 4010;
const VULNERABLE = process.env.VULNERABLE === '1';
const SHARED_SECRET = 'frugal-demo-shared-secret';   // demo only
const SALT = 'frugal-salt-seq-7f3a';                  // salt sequence agreed out of band
const MAX_SKEW_MS = 30_000;

const transactions = new Map();   // id -> { challenge, challengeUsed, body, status }
const seenMacs = new Set();       // replay cache

const send = (res, code, body, headers = {}) => {
  res.writeHead(code, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
};

const readBody = (req) => new Promise((resolve) => {
  let data = '';
  req.on('data', (c) => (data += c));
  req.on('end', () => resolve(data));
});

function expectedMac(rawBody, tsMicros, challenge) {
  return crypto
    .createHmac('sha512', SHARED_SECRET)
    .update(`${rawBody}.${tsMicros}.${challenge}.${SALT}`)
    .digest('hex');
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const raw = await readBody(req);

  // 1) POST /transactions -> creates wrapper, returns ID + challenge token in HEADERS
  if (req.method === 'POST' && url.pathname === '/transactions') {
    const id = 'txn_' + crypto.randomBytes(6).toString('hex');
    const challenge = crypto.randomBytes(16).toString('hex');
    transactions.set(id, { challenge, challengeUsed: false, status: 'created' });
    return send(res, 201, { message: 'created' }, {
      'X-Transaction-Id': id,
      'X-Challenge-Token': challenge,
      'X-Server-Timestamp': String(Date.now()),
    });
  }

  // 2) PUT /transactions/:id -> requires X-Frugal-Mac, X-Frugal-Timestamp (microseconds), X-Challenge-Token
  const m = url.pathname.match(/^\/transactions\/(txn_[a-f0-9]+)$/);
  if (req.method === 'PUT' && m) {
    const txn = transactions.get(m[1]);
    if (!txn) return send(res, 404, { error: 'unknown transaction' });

    const mac = req.headers['x-frugal-mac'];
    const ts = req.headers['x-frugal-timestamp'];
    const challenge = req.headers['x-challenge-token'];
    if (!mac || !ts || !challenge) return send(res, 400, { error: 'missing security headers' });

    if (challenge !== txn.challenge) return send(res, 401, { error: 'bad challenge token' });

    const tsMs = Number(ts) / 1000;
    if (!Number.isFinite(tsMs) || Math.abs(Date.now() - tsMs) > MAX_SKEW_MS)
      return send(res, 401, { error: 'timestamp outside allowed skew' });

    const good = expectedMac(raw, ts, challenge);
    const a = Buffer.from(good), b = Buffer.from(String(mac));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b))
      return send(res, 401, { error: 'invalid X-Frugal-Mac' });

    // Replay protection: a MAC may be consumed exactly once.
    if (!VULNERABLE && seenMacs.has(mac))
      return send(res, 409, { error: 'replay detected', code: 'REPLAY_REJECTED' });
    seenMacs.add(mac);

    txn.body = JSON.parse(raw || '{}');
    txn.status = 'updated';
    return send(res, 200, { id: m[1], status: 'updated', echoed: txn.body });
  }

  send(res, 404, { error: 'not found' });
});

if (require.main === module) {
  server.listen(PORT, () =>
    console.log(`[mock-gateway] listening on :${PORT}  mode=${VULNERABLE ? 'VULNERABLE (no replay guard)' : 'SECURE'}`));
}
module.exports = { server };
