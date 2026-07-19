# Payment OAuth Refactor — Security & Architecture Audit

**Date:** 2026-07-19
**Auditor:** Read-only security & architecture review (no code, GitHub, or Railway state modified)

**Scope**

| Repo | GitHub | PR | Production merge (audited @ origin/main) |
|---|---|---|---|
| AdmitOneConnect (broker "Connect") | `Xarindar/AdmitOneConnect` | #1 | `e0f2f588efa0288d5f6d32131efc0edc22829eef` |
| AdmitScheduling / Showrunner | `Xarindar/showrunner` | #4 | `16575e119a663ac2081f35d528981896c0b3c9fc` |

Both repos were audited from clean **detached snapshots pinned to the production merge commits**, so the dirty working trees were never touched. Railway project `20900b03-1e55-4afc-b525-23d4b80c65f2` was inspected read-only.

---

## Bottom line

**No Critical or High severity issues, and no confirmed confidentiality or integrity vulnerability.** The intended architecture is implemented faithfully and holds up under adversarial testing: Square end-to-end PKCE with the verifier retained only by Showrunner, Connect never seeing Square tokens, Stripe exchanged once and used directly thereafter, payment runtime fully independent of Connect, and the removed Square broker endpoints unreachable in production.

The one material item is a **Medium reliability defect**: a crash/rollback window in the Square refresh worker can permanently invalidate a merchant's refresh token (confirmed, because Square PKCE refresh tokens are single-use rotating). Everything else is Low or defense-in-depth.

---

## Verification performed (all green)

| Check | Connect | Showrunner |
|---|---|---|
| `tsc` typecheck | ✅ 0 errors | ✅ 0 errors |
| Build | ✅ `tsc` | ✅ prisma generate + `prisma validate` |
| Unit/security tests | ✅ 4/4 | ✅ 6/6 |
| Lint | ✅ (`tsc`) | ✅ eslint 0 errors (3 unrelated warnings) |
| `npm audit` (prod + all) | ✅ 0 vulnerabilities | ✅ 0 vulnerabilities |
| Adversarial suite (added for this audit) | ✅ 8/8 | — |

**Railway production (read-only; authoritative GraphQL resolved-variable set, values never read):**

- **Connect service `3bc48992-89eb-4d9d-a5e6-c85456321c46`** — running audited commit `e0f2f58`, 2 replicas RUNNING, live `GET /health` → `200 {"ok":true}` with CSP `default-src 'none'`, HSTS preload, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`. Startup log: `AdmitOne Connect listening on :8080` (no config-error output). **`SQUARE_APP_SECRET` is absent** (25 vars: only public `SQUARE_APP_ID` / `SQUARE_OAUTH_ENV` / `SQUARE_API_VERSION`, plus `STRIPE_PLATFORM_SECRET_KEY`, `STRIPE_CONNECT_CLIENT_ID`, `ADMITONE_CONNECT_SIGNING_SECRET`, `ADMITONE_CONNECT_CLIENTS`, `BROKER_PUBLIC_URL`, `DATABASE_URL`).
- **Live removed-endpoint probes:** `GET /connect/square/refresh` → **404**, `GET /connect/square/revoke` → **404** (catch-all 404 handler; only `/connect/stripe/revoke` exists).
- **Square cron `0dda6c82-a848-4f58-8d7e-1b1411e25d1d` (`square-token-refresh`)** — commit `16575e1`, config `railway.square-refresh.json`, `cronSchedule: 17 3 * * *` (daily 03:17 UTC), `startCommand: npm run payments:refresh-square`, `restartPolicyType: NEVER`, **no health path, no custom/service domains (unexposed)**, last run `EXITED` cleanly (`candidates=0 failures=[] refreshed=0 staleConnections=[]`), holds `PAYMENT_CREDENTIAL_ENCRYPTION_KEY` + `DATABASE_URL` (can decrypt/rotate). **No `SQUARE_APP_SECRET`.**
- **Showrunner `785c8f23-f571-4abd-8f72-8b783de6a960`** — commit `16575e1`, 2 replicas RUNNING, has `PAYMENT_CREDENTIAL_ENCRYPTION_KEY`, `AUTH_SECRET`, `ADMITONE_CONNECT_SHARED_SECRET`; no platform/Square app secrets.

**Adversarial suite (8/8 pass)** — confirmed the broker rejects: cross-tenant handoff redemption (409 wrong tenant / 401 forged signature), provider substitution (stripe handoff redeemed as square → 409), nonce tampering (409), cross-provider state replay at the wrong callback (400), `returnUrl` outside the registered origin (400), Stripe-with-PKCE and malformed Square PKCE (400), broker-state forged with the client secret instead of the broker secret (400), and handoff replay after success (409).

---

## Findings (ranked)

### 🔴 Critical — none

### 🟠 High — none

### 🟡 Medium

#### M1 — Square refresh-token rotation has an unguarded crash/commit window that can permanently brick a merchant's connection

**File:** `showrunner/lib/payments/connect/square-refresh.ts:172-231` (`refreshSquareCredentialDirect`)

The rotation HTTP call to Square runs *inside* the Prisma transaction (`refreshSquarePkceToken`, `square-refresh.ts:202`), and the DB write that persists the new tokens runs afterward (`:212-225`), committing at `:229`. Square PKCE refresh tokens are **single-use and rotating** — confirmed against Square's OAuth docs: the PKCE flow returns a *new* refresh token and invalidates the old one (unlike the non-PKCE code flow, which reuses the same refresh token).

**Failure scenario (no attacker required):** the cron acquires the advisory lock, decrypts the old refresh token, and calls Square, which rotates it (old token now dead at Square). If the process is then killed (Railway SIGTERM during redeploy, the 20 s transaction timeout firing mid-commit at `:229`, a Postgres failover, or a pod eviction) before the transaction commits, the DB rolls back to the *old, now-invalid* refresh token and the new token is lost forever. Every subsequent refresh sends the dead token → Square returns `invalid_grant` → the credential can no longer refresh. The 30-day access token keeps payments working for up to ~23 more days (cadence is 7 days), then `getSquareAccessToken` (`credentials.ts:176`) throws "connection expired," and the merchant must manually reconnect.

**Why Medium, not High:** requires an unlucky crash in a narrow window; the cron runs a single replica (low concurrency); ~23-day recovery buffer; currently zero connected merchants. But it is a *confirmed* correctness defect, not hardening.

**Recommended fixes (any one closes most of the gap):**
1. **Tolerate both tokens.** Persist the previous refresh token alongside the current one; on `invalid_grant`, retry once with the other. Survives a lost commit because whichever token Square still honors will work.
2. **Detect `invalid_grant` → downgrade + alert.** On a refresh failure that is specifically an invalid/expired refresh token, set the credential `status = ERROR` and surface a "reconnect Square" prompt, instead of leaving it `CONNECTED` and silently failing daily (see L1).
3. Keep the Square call inside the transaction (that ordering is deliberate and correct for advisory-lock atomicity) but shrink the exposure — the DB `update` is already the next statement; additionally consider committing the freshly received refresh token in its own statement immediately.

### 🟢 Low

#### L1 — A failed/stale Square refresh is only signaled by cron exit code; the credential is never flagged for reconnect
**File:** `showrunner/scripts/refresh-square-tokens.ts:44-57`

Failures are collected into `failures[]` and staleness (>8 days) into `stale[]`, and the process sets `exitCode = 1` — but the credential row stays `CONNECTED` with no per-credential status change or operator alert. This is the detection gap that lets M1 silently ride out the 30-day access-token window. **Fix:** on refresh failure mark the credential `ERROR`/needs-reconnect and emit an alert; treat `refresh_token_expires_at` proactively.

#### L2 — Connect docs still instruct operators to provision `SQUARE_APP_SECRET`, which the code no longer uses
**Files:** `AdmitOneConnect/SETUP-KEYS.md:32,59`, `plan.txt:81`, `SECURITY-AUDIT.md:110`

The code path that consumed it (`exchangeSquareCode` / `refreshSquareToken` / `revokeSquareAccess`) was deleted in PR #1, and `src/lib/config.ts` no longer reads it. Production is clean (verified), so this is documentation hygiene: the stale docs could lead an operator to paste a high-value Square secret into the broker env where it would sit unused. **Fix:** remove `SQUARE_APP_SECRET` from the setup docs.

#### L3 — Square OAuth "disconnect" wipes local tokens but cannot revoke them at Square (by design)
**File:** `showrunner/lib/payments/provider-onboarding.ts:242-293`

The Connect-revoke branch is gated on `provider === STRIPE` (`:248`); Square OAuth disconnect falls through to the local wipe (`:278-292`, status `REVOKED`) with no provider-side revocation. This is the correct consequence of the no-secret PKCE model (Showrunner has no Square app secret to call `/oauth2/revoke`), but a disconnected Square merchant's tokens remain valid at Square until they expire or the merchant revokes app access from their Square dashboard. **Fix:** document in the disconnect UX; not a code fix.

---

## Defense-in-depth (not vulnerabilities)

- **D1 — PKCE verifier travels in a signed-but-unencrypted nonce cookie.** `showrunner/lib/payments/connect/flow.ts:88-98` puts `codeVerifier` into `signConnectToken` (HMAC-signed, base64url payload, *not* encrypted). Confidentiality rests entirely on the cookie flags, which are set correctly — `httpOnly`, `secure` in production, `sameSite:lax`, `path:/api/payments/connect`, 10-min TTL (`app/api/payments/connect/[provider]/start/route.ts:34-40`). Even if exposed, the verifier is useless without the matching Square authorization code (which only ever reaches Showrunner via server-to-server handoff redemption). Optional: seal/encrypt the cookie payload so the verifier isn't recoverable at rest.
- **D2 — Webhook signature verification tries every tenant's secret (pre-existing, not in this refactor).** `lib/commerce/stripe.ts:461-478` and `lib/commerce/square.ts:433-437` iterate all connected sites' secrets. Amount/currency cross-checks and Stripe/Square-generated object IDs make cross-tenant forgery impractical, and forging still requires *some* valid signing secret. These files were untouched by PR #4. Optional: bind an event to its site by connected-account/merchant ID before matching.
- **D3 — Abandoned Stripe authorizations aren't auto-deauthorized.** If an admin authorizes Stripe but never completes redemption, Connect's compensation only fires on a handoff-store failure (`AdmitOneConnect/src/server.ts:275-289`), not on non-redemption; the handoff expires but the Stripe authorization lingers until reconnect. Benign.

---

## Architecture conformance (each intended guarantee, confirmed)

- **Connect used only for the browser OAuth flow** — ✅ runtime charge/refund/webhook/checkout read stored tokens and call providers directly; the only Connect calls are onboarding (`flow.ts`) and Stripe disconnect/compensation (`broker-client.ts`). Enforced by a guard test (`test/connect-security.test.ts:191-207`).
- **Stripe exchanged once by Connect, then Showrunner calls Stripe directly** — ✅ `getStripeApiKeyForSite` (`credentials.ts:106-119`) returns the OAuth access token directly; `getStripeForSite` (`commerce/stripe.ts:28-35`) uses it with no `stripeAccount` and no Connect.
- **Connect used only for explicit Stripe disconnect/compensation, never payment runtime** — ✅ (`provider-onboarding.ts:262`, `flow.ts:264`).
- **Square end-to-end PKCE; Showrunner generates & retains the verifier; Connect sees only challenge + short-lived code** — ✅ verifier created and kept in Showrunner (`square-refresh.ts:113-117`, `flow.ts:66`), only `codeChallenge` sent to Connect (`flow.ts:76`); Connect's Square handoff carries *only* `authorizationCode` + public metadata (`AdmitOneConnect/src/lib/providers.ts:125-136`), asserted by test (`security.test.ts:124-133`).
- **Connect never receives/stores/logs/exchanges/refreshes/revokes Square tokens** — ✅ no code path exists; `revokeProviderAccess` throws for Square (`providers.ts:143-145`); live `/connect/square/refresh` and `/connect/square/revoke` → 404.
- **Showrunner exchanges/encrypts/rotates Square tokens directly** — ✅ (`flow.ts:294-357`, `square-refresh.ts`), AES-256-GCM via HKDF (`credential-crypto.ts`), single-use refresh handled directly.
- **Refresh worker shares the codebase, runs as a separate daily cron** — ✅ `scripts/refresh-square-tokens.ts` + separate Railway service (verified above).
- **Payment execution continues if Connect is down** — ✅ no runtime dependency; confirmed by grep + guard test.
- **No Stripe token duplicated into legacy secret-key fields** — ✅ `secretKey:""` for OAuth (`flow.ts:252`), guard test asserts no `secretKey: accessToken` (`connect-security.test.ts:206`).
- **No legacy compatibility** — ✅ the only "backward-compat" branch is the ownership-map bootstrap in Connect revoke (`server.ts:337-349`), gated to a single-client registry and not a payment path.
- **Encryption & key separation** — ✅ Connect seals handoffs with the broker signing secret (HKDF-per-type, `AdmitOneConnect/src/lib/tokens.ts:84-104`); Showrunner encrypts credentials with a *separate* `PAYMENT_CREDENTIAL_ENCRYPTION_KEY`; the DB stores only sealed payloads and SHA-256 digests of the opaque code/nonce.
- **Replica races & advisory locking** — ✅ `pg_try_advisory_xact_lock` + an in-transaction cadence re-check (`square-refresh.ts:178-188`) correctly prevents double rotation; production cron is single-replica and the web app never refreshes.
- **Handoff redemption auth + one-time consumption** — ✅ HMAC service-request signature over method/path/tenant/time/nonce/body (`request-auth.ts`), replay store (`registerRequest`), and one-time `DELETE ... RETURNING` consume (`artifact-store.ts:288-327`).
- **Removed Square broker refresh/revoke endpoints unreachable** — ✅ deleted in source (PR #1) and 404 in live production.
- **Cron unexposed, runs `npm run payments:refresh-square`, daily, and exits** — ✅ all four confirmed on Railway.
- **Connect production has no `SQUARE_APP_SECRET`** — ✅ confirmed via authoritative GraphQL variable set.

---

## Residual risks / flows that could not be fully exercised

- **Live Stripe/Square token exchange, webhook signatures, and refunds** need real provider accounts and sandbox credentials; verified by code trace, mocked-`fetch` unit tests, and schema/flow, not against live Stripe/Square. The M1 crash window in particular can only be *proven* end-to-end with a real Square PKCE credential and an induced crash.
- **Secret *values*** on Railway were deliberately not read; only variable presence/absence was confirmed. Shared-secret consistency between Connect's `ADMITONE_CONNECT_CLIENTS` and Showrunner's `ADMITONE_CONNECT_SHARED_SECRET` is implied by healthy operation, not value comparison.
- **Priorities:** M1 (confirmed, Medium) first, then L1 and L3. Only M1 is a confirmed defect.

---

## Appendix — what was run

- Snapshots: `git clone` of each repo into scratch, `git checkout --detach <merge-commit>`, `npm ci`.
- Connect: `tsc --noEmit`, `npm run build`, `npm test` (4/4), `npm audit` (0), plus `test/adversarial.test.ts` (8/8, added for this audit).
- Showrunner: `prisma validate` + `prisma generate`, `npm test` (6/6), `eslint .` (0 errors), `tsc --noEmit` (0), `npm audit --omit=dev` (0).
- Railway (read-only): `railway status --json`, `railway variable list` (names only), GraphQL `variables` query for authoritative resolved variable names, `railway logs` for Connect + cron, and a live `curl` of `https://connect.admitonedesign.com/health` plus 404 probes of the removed Square endpoints.
