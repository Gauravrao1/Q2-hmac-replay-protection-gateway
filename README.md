# Q2 HMAC Replay Protection Gateway

A dependency-free Node.js mock payment gateway and security test suite for
validating request authentication and replay protection.

## What it tests

- `POST /transactions` returns a transaction ID, challenge token, and server timestamp.
- `PUT /transactions/{id}` validates a dynamically generated `X-Frugal-Mac`
  using HMAC-SHA512 over the request body, microsecond timestamp, challenge,
  and salt.
- Replaying the identical packet within the 150 ms test budget is rejected
  with HTTP 409.
- Tampered request bodies and stale timestamps are rejected with HTTP 401.
- `VULNERABLE=1` disables replay protection so the test can demonstrate and
  report the resulting high-risk data-mutation vulnerability.

## Requirements

- Node.js 18 or newer

## Run the secure gateway and test

In one terminal:

```powershell
npm run server
```

In another terminal:

```powershell
npm test
```

The secure test should finish with `ALL CHECKS PASSED`.

## Demonstrate the vulnerable mode

In one terminal:

```powershell
npm run server:vulnerable
```

In another terminal:

```powershell
BASE_URL=http://localhost:4011 npm test
```

The test intentionally exits non-zero after reporting that the replayed
packet was accepted with a duplicate success response.

## Project files

- `mock-server.js` - dependency-free mock gateway.
- `q2-replay-test.js` - chained request and replay-security test.
- `run-logs/` - captured secure and vulnerable test runs.
