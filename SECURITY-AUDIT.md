# Security Audit — Admit One Connect, Railway Deployment, and Showrunner Integration

**Audit date:** 2026-07-18
**Auditor:** Claude (main agent) with four dedicated read-only branch sub-agents (Connect app-sec, Railway/ops, Showrunner integration, provider config + threat model), followed by independent main-agent verification of every Critical/High/Medium finding.
**Targets:**
- Connect broker repo `Xarindar/AdmitOneConnect` (local `C:\Users\Abe Tannenbaum\Documents\AdmitOneConnect`)
- Live broker `https://connect.admitonedesign.com` (Railway project "Admit One", service `connect`)
- Showrunner `Xarindar/showrunner` (live `https://admin.admitonedesign.com`)
- Stripe Connect (Standard OAuth) + Square OAuth provider configuration

**Nature of engagement:** Read-only audit and reporting. No application code was modified, nothing was deployed, no credentials were rotated, no provider settings changed, no merchant account connected, no transaction created, no Git changes pushed. All external interactions were read-only and non-destructive. All secret values are redacted throughout; secrets were verified only by name/presence/prefix.

> **This report supersedes an earlier `SECURITY-AUDIT.md` that audited a pre-remediation version of the broker.** That report's headline High (Stripe/Square merchant credentials passed through the browser in a signed-but-unencrypted handoff query parameter), along with non-atomic replay consumption, single-replica deployment, and EOL Node 20, have since been **remediated** on the current `main` (commits "Patch OAuth broker security issues" and "Complete OAuth broker security remediation") and were re-verified as fixed during this audit: the handoff is now an opaque 256-bit single-use code with an authenticated back-channel redeem, one-time consumption is atomic in Postgres, the service runs 2 replicas on Node 24, and a test asserts no provider token ever reaches the browser URL.

---

## 1. Executive summary

Admit One Connect is a small, unusually well-engineered OAuth broker whose job is to hold the platform-level Stripe Connect and Square credentials, complete the merchant OAuth handshake, and hand merchant tokens back to a client Showrunner deployment over an authenticated back-channel — without ever putting provider tokens on the browser URL. The cryptographic core is sound and the deployment posture is strong. Across three codebases and the live service, the audit found **no Critical vulnerability, no committed secret, no dependency advisory, and no authentication-bypass, signature-forgery, or open-redirect defect.**

The audit did confirm **one High and three Medium** issues, all of which are addressable without architectural upheaval:

- **AOC-01 (High):** The broker's `POST /connect/:provider/revoke` authenticates the *caller* but never binds the supplied `externalAccountId` to that caller. In a multi-client broker, any one registered client can deauthorize another tenant's Stripe/Square merchant — a cross-tenant availability break.
- **AOC-02 (Medium):** The broker's OAuth callback has no broker-side browser-session binding (no cookie set at `/start`). If a live, unconsumed signed `broker_state` leaks, an attacker can inject their own provider authorization code and cause the victim site to store the attacker's merchant account (payment redirection).
- **AOC-03 (Medium):** The `main` branch is unprotected on a **public** repository that Railway auto-deploys — a single unreviewed push reaches production, which holds every platform and client secret.
- **AOC-04 (Medium):** Provider credentials are not prefix/type-validated at startup, so a swapped env var (e.g. the platform secret key pasted into the client-id variable) would embed the platform secret key in the browser-facing authorize redirect.

The remaining items are Low/Informational hardening. One sub-agent finding (provider error-text disclosure) was **disproved** during verification and is documented as a false positive.

A material scope limitation: the **Railway CLI was unauthenticated** for the entire engagement, so live variable names, secret sealing, cross-service isolation, actual replica/region, deployment drift, and runtime logs could not be inspected directly. Those items are called out as unverified. Provider dashboard settings (registered redirect URIs, actual live/test key modes, exact registered scopes) are likewise unverifiable without dashboard access.

## 2. Overall security posture

**Strong.** This is a defensively-built system. Highlights confirmed first-hand:

- **Token crypto:** HMAC-SHA256 signed tokens and AES-256-GCM sealed tokens, with **per-token-type HKDF key derivation plus GCM AAD = token type**, which structurally prevents cross-type/cross-provider token confusion. `exp` is enforced on every token; comparisons are constant-time and length-hiding.
- **Replay/one-time semantics** are enforced in shared Postgres via atomic `DELETE … RETURNING` (state, handoff) and `INSERT … ON CONFLICT DO NOTHING` (request-id), so they hold across the two production replicas. The request-id replay table is written **only after** signature verification, so unauthenticated callers cannot pre-burn a victim's request-ids.
- **No provider token ever reaches the browser URL** — only an opaque 256-bit single-use code does; tokens travel over an HMAC-signed back-channel bound to method, path, body digest, client, site, provider, timestamps, and request-id.
- **Return URL is origin-pinned** to the client's registered origin (embedded credentials rejected) — no open redirect or SSRF found.
- **Browser round-trip is nonce-bound** (Showrunner httpOnly signed cookie) — defeats handoff injection and OAuth merchant-confusion in the normal flow.
- **Production hardening:** pinned non-root multi-stage Alpine image, `npm ci --ignore-scripts`, `npm prune --omit=dev`, 32 KB body cap, request/header/keep-alive timeouts, provider concurrency cap + circuit breaker, strict security headers (CSP `default-src 'none'`, HSTS, nosniff, frame-deny), TLS 1.3 with a valid Let's Encrypt certificate, redacted logging, `x-powered-by` disabled.
- **Clean supply chain:** broker `npm audit` = 0 vulnerabilities; minimal dependency surface (express, pg, dotenv). No secrets in any repo's Git history.

The gaps that remain are about **tenant-authorization completeness at the broker** (AOC-01), **defense-in-depth on the OAuth callback** (AOC-02), and **operational/CD integrity** (AOC-03, AOC-04) — not about broken cryptography or exposed secrets.

## 3. Scope and methodology

**In scope:** the Connect broker code and live deployment; the Showrunner payment-connect integration (`lib/payments/connect/**`, `app/api/payments/connect/**`, `lib/payments/credential-crypto.ts`, webhook verification); Stripe/Square OAuth configuration as expressed in code and confirmed against current official docs; and an end-to-end threat model.

**Out of scope / excluded:** `Xarindar/admitone` (confirmed to be the static marketing/studio website, unrelated to payments); the full Showrunner application beyond the payment-connect surface; provider dashboard internals; and any mutating/production-changing action.

**Method:**
1. First-hand read of all 13 broker source files, the broker test, docs, CI, Dockerfile, and railway.json.
2. Cloned and read the Showrunner integration and its crypto/auth/site/webhook code; identified `admitone` as out of scope.
3. Secret-exposure scan across all Git history of all three repos using high-entropy real-key regexes with **values suppressed** (redacting sed filter). Result: no committed secrets.
4. Dispatched four bounded, read-only branch sub-agents (one per audit branch) with strict secret-handling rules; required structured evidence.
5. Independent main-agent verification: clean build, typecheck, tests, `npm audit`, live non-destructive negative-route probes, live TLS inspection, and direct re-reading of the cited code for every Critical/High/Medium finding. Reproduced findings where safe.
6. Reconciled agent findings, removed duplicates, adjudicated severity conflicts, and demoted one false positive.

**Tooling status:** Node 22.17 / npm 10.9 local; gh authenticated (Xarindar); **Railway CLI unauthenticated** (interactive `railway login` deliberately not invoked); `jq` unavailable (worked around with node/sed). Live broker reachable and healthy.

## 4. Architecture and trust-boundary diagram

```
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │ TRUST BOUNDARY A — Merchant's browser (admin user, untrusted transport)       │
  │                                                                               │
  │   Admin ──(1) GET /admin ...──▶ Showrunner (admin.admitonedesign.com)          │
  │        ◀─(2) 302 to broker /connect/{p}/start?client_id&state=<signed CS>─     │
  │        + Set-Cookie connect_nonce=<signed, httpOnly, SameSite=Lax>            │
  └───────────────────────────────────┬───────────────────────────────────────────┘
                                       │  (broker_state travels in browser URL here)
  ┌────────────────────────────────────▼──────────────────────────────────────────┐
  │ TRUST BOUNDARY B — Connect broker (connect.admitonedesign.com, Railway)         │
  │   • Holds ONE Stripe platform secret + ONE Square app secret (shared)          │
  │   • Holds ADMITONE_CONNECT_SIGNING_SECRET + per-client shared secrets          │
  │   • Postgres one-time store (state / request / handoff)                         │
  │                                                                                 │
  │   /start   verify CS (client secret) → sign broker_state (broker secret)        │
  │            → register one-time stateId → 302 to provider  [NO broker cookie]     │
  │   /callback verify broker_state → consumeState → exchange code (PLATFORM key)    │
  │            → seal handoff (AES-GCM) → 302 to returnUrl?code=<opaque 256-bit>     │
  │   /handoff/redeem  HMAC service-req (client secret) → consumeHandoff             │
  │   /square/refresh  HMAC service-req → open client-sealed handle → provider       │
  │   /revoke          HMAC service-req → provider deauthorize   ◀── AOC-01 gap      │
  └───────────┬───────────────────────────────────────────────┬─────────────────────┘
              │ (2-way TLS to providers, platform creds)        │ (back-channel, TLS + HMAC)
  ┌───────────▼──────────────────┐             ┌────────────────▼─────────────────────┐
  │ TRUST BOUNDARY C — Providers │             │ TRUST BOUNDARY D — Showrunner server  │
  │ Stripe connect.stripe.com    │             │ (one deployment = one client/tenant)  │
  │ Square connect.squareup.com  │             │ • requireAdmin (global admin identity)│
  │ (consent, code, tokens,      │             │ • siteId = resolveCurrentSite(host)   │
  │  deauthorize/revoke)         │             │ • stores merchant tokens AES-256-GCM  │
  └──────────────────────────────┘             │ • charges provider DIRECTLY (broker   │
                                               │   is NOT in the payment path)         │
                                               └───────────────────────────────────────┘
```

**Key trust facts (verified):**
- The **broker is the shared multi-tenant component**: one Stripe platform account + one Square app serve all registered clients (`ADMITONE_CONNECT_CLIENTS`).
- **Each Showrunner deployment is single-tenant** (one `client_id`, default site; `AdminUser` has no site/tenant binding; `siteId` derived from request hostname). Multiple clients = multiple separate Showrunner deployments.
- Therefore the **cross-tenant attack surface concentrates at the broker**, on any route that is not client-bound. Only `/revoke` is unbound (AOC-01); `handoff/redeem` and `square/refresh` are fully client+site+nonce bound.
- The broker signs `broker_state` with a **broker-only** secret that no client possesses, so a compromised client cannot forge broker state or impersonate another `client_id`.

## 5. Sensitive assets and data-flow inventory

| Asset | Where it lives | Protection | Exposure if lost |
|---|---|---|---|
| `STRIPE_PLATFORM_SECRET_KEY` (sk_live) | Broker env only | Env var; used only for outbound token/deauthorize | Act on/deauthorize all connected Standard accounts |
| `SQUARE_APP_SECRET` | Broker env only | Env var; used only for outbound token/revoke | Refresh/revoke all Square merchant tokens |
| `ADMITONE_CONNECT_SIGNING_SECRET` | Broker env only | HMAC for broker_state + HKDF root for handoff AEAD | Forge broker_state; open/seal handoffs |
| Per-client shared secret | Broker registry env + each Showrunner env | HMAC client_state + service-request signatures | Impersonate that one client |
| Merchant Stripe access token (= merchant sk_live) | Handoff (sealed, transient) → Showrunner DB (AES-256-GCM) | Sealed in transit; encrypted at rest | Full control of that merchant's Stripe |
| Merchant Square access/refresh tokens | Square refresh handle (client-sealed) → Showrunner DB (AES-256-GCM) | Sealed + tenant-bound; encrypted at rest | Charge/refresh that merchant's Square |
| Opaque handoff code | Browser URL (single-use, 5-min) | 256-bit random; consumed atomically | Redeem requires ALSO client secret + nonce |
| `broker_state` (signed) | Browser URL during provider hop (10-min, single-use) | HMAC-signed, one-time stateId | Code-injection window (AOC-02) |
| Postgres (state/request/handoff) | Railway | Only digests + sealed payloads stored | Sealed payloads still need signing secret |

**Primary data flow:** admin → Showrunner `/start` (auth) → signed client_state + nonce cookie → broker `/start` → provider consent → broker `/callback` exchanges code with **platform** creds → seals handoff, returns opaque code → Showrunner `/callback` redeems over HMAC back-channel → stores merchant tokens encrypted → **Showrunner charges the provider directly** (broker leaves the path).

## 6. Attack-surface inventory

**Broker (public, internet-facing):**
- `GET /health` (rate 60/min) — real DB ping.
- `GET /connect/:provider/start` (20/10min) — requires client-signed `state` + known `client_id`.
- `GET /connect/:provider/callback` (30/10min) — requires broker-signed `state`.
- `POST /connect/handoff/redeem` (60/5min) — HMAC service-request auth.
- `POST /connect/square/refresh` (60/5min) — HMAC service-request auth.
- `POST /connect/:provider/revoke` (30/10min) — HMAC service-request auth. **AOC-01**.
- Global limiter 300/min; 32 KB JSON cap; 404 + generic error handler.

**Showrunner (payment-connect surface):**
- `GET /api/payments/connect/[provider]/start` — `requireAdmin("settings:update")`.
- `GET /api/payments/connect/[provider]/callback` — `requireAdmin` + nonce cookie.
- Server actions (location selection, disconnect) — `requireAdmin` + server-derived site.
- `POST /api/webhooks/stripe` / `/square` — provider signature verification.

**Providers:** Stripe/Square authorize, token, deauthorize/revoke, refresh endpoints (outbound only).

**Repo/CD:** public GitHub repo → Railway auto-deploy from `main`. **AOC-03**.

## 7. Prioritized findings table

| ID | Title | Severity | Status | Confidence | Component | Local/Prod |
|----|-------|----------|--------|-----------|-----------|-----------|
| AOC-01 | Cross-tenant merchant revocation (`/revoke` not bound to caller) | **High** | Verified | High | Broker `server.ts`/`providers.ts` | Both |
| AOC-02 | OAuth callback lacks broker-side browser binding (code injection if `broker_state` leaks) | **Medium** | Verified (design gap) | Medium | Broker `server.ts` `/start`+`/callback` | Both |
| AOC-03 | `main` unprotected + public repo + Railway auto-deploy | **Medium** | Verified | High | GitHub/Railway CD | Prod |
| AOC-04 | No provider-credential prefix/type validation (env-swap leaks platform secret) | **Medium** | Verified | High | Broker `config.ts` | Both |
| AOC-05 | Per-replica in-memory rate limiting (weaker throttles; resets on deploy) | Low | Verified | High | Broker `rate-limit.ts` | Prod |
| AOC-06 | Payment-credential key falls back to `AUTH_SECRET`; raw SHA-256 (no HKDF/salt) | Low | Verified | High | Showrunner `credential-crypto.ts` | Both |
| AOC-07 | Global admin identity + Host-header site resolution (latent cross-site) | Low (conditional) | Partially verified | Medium | Showrunner `auth.ts`/`site.ts` | Both |
| AOC-08 | No minimum length/entropy check on broker secrets | Low | Verified | High | Broker `config.ts`/`registry.ts` | Both |
| AOC-09 | CI lacks image scan / secret scan / SBOM; audit gate high-only | Low | Verified | High | `.github/workflows/security-ci.yml` | Both |
| AOC-10 | Stripe `read_write` hands off & stores merchant live key; deprecated token fields | Low | Verified | High | Broker `providers.ts` / Showrunner `flow.ts` | Both |
| AOC-11 | Dead code `src/lib/signatures.ts` (weaker body-only signature) | Info | Verified | High | Broker `signatures.ts` | n/a |
| AOC-12 | Stripe `livemode` surfaced but not enforced by broker | Info | Verified | High | Broker `providers.ts` | Prod |
| AOC-13 | `request_id` at exact 32-char minimum (brittle contract coupling) | Info | Verified | High | Showrunner `broker-client.ts` | Both |
| AOC-14 | Square authorize omits `redirect_uri` (relies on dashboard) | Info | Partially verified | Medium | Broker `providers.ts` | Prod |
| AOC-15 | Railway edge version headers + HSTS lacks `preload` | Info | Verified | High | Live edge / `server.ts` | Prod |
| AOC-16 | Plaintext env secrets, no KMS envelope (accepted architectural risk) | Info | Verified | High | Broker/Showrunner env | Prod |
| AOC-17 | Framework 4xx error messages reflected (JSON-parse/413) | Info | Verified | Medium | Broker `server.ts` error handler | Both |
| — | (FALSE POSITIVE) Provider `error_description` disclosure on refresh/revoke | — | Disproved | — | Broker `server.ts` | — |

Severity mix: **1 High, 3 Medium, 6 Low, 7 Informational.** No Critical.

## 8. Detailed verified findings

### AOC-01 — Cross-tenant merchant revocation: `externalAccountId` not bound to the calling client
- **Severity:** High · **Status:** Verified · **Confidence:** High · **Applies:** local + production
- **Component / route:** Broker `POST /connect/:provider/revoke`
- **Exact location:** `src/server.ts:353-367` (handler), `src/server.ts:501-512` (`validateRevokeBody`), `src/server.ts:421-446` (`authenticateServiceRequest`), `src/lib/providers.ts:177-229` (`revokeProviderAccess`/`revokeStripeAccess`/`revokeSquareAccess`).
- **Evidence (redacted):** The handler validates `externalAccountId` only as a non-empty string ≤255 chars, authenticates the *client* envelope (HMAC over method/path/body + one-time request-id), then calls `revokeProviderAccess(config, provider, { externalAccountId: body.externalAccountId })` using the **shared platform** Stripe secret / Square app secret. The store persists **no** `externalAccountId → client_id` mapping (the only per-merchant record, the handoff, is deleted at redeem). A `grep` for any ownership/binding check in `src/` returns nothing beyond the raw pass-through. Contrast `consumeHandoff` (`src/lib/artifact-store.ts:190-218`), which *does* bind `client_id`+`site_id`+`provider`+`nonce`.
- **Attack prerequisites:** Attacker holds a valid `client_id` + shared secret (is, or has compromised, a registered client) **and** knows a victim tenant's provider account id — a Stripe `acct_…` id or a Square `merchant_id`. These identifiers are semi-public (appear in dashboards, receipts, API responses, URLs).
- **Concrete exploit scenario:** Registered client A signs a well-formed request to `POST /connect/stripe/revoke` (or `/square/revoke`) with `externalAccountId` = client B's merchant id. The broker calls Stripe `/oauth/deauthorize` (or Square `/oauth2/revoke`) under the platform account and succeeds — Stripe even echoes back the same `stripe_user_id`, so the success guard at `providers.ts:204` passes. Client B's merchant is disconnected and its checkout breaks until B re-onboards.
- **Business/technical impact:** Cross-tenant availability/integrity break — one tenant can sever arbitrary other tenants' payment processing. Not credential exposure or account takeover (hence High, not Critical). In a payments platform, an attacker disabling a competitor's checkout is materially damaging.
- **Remediation:** Bind revocation authority to the caller. Preferred: at handoff time, seal a per-merchant, client-secret-sealed "revoke capability" (e.g. `typ: admitone.revoke` containing `clientId`, `siteId`, `provider`, `externalAccountId`) exactly as the Square refresh handle is sealed; on `/revoke`, `open()` it with the caller's secret and require `clientId === body.client_id` before calling the provider. Alternative: persist an `externalAccountId → (clientId, siteId)` binding at connect time and enforce it. Reject any account not owned by the caller.
- **Recommended verification test:** Add a test where client A onboards merchant M, then client B (valid creds) calls revoke with M's id; assert `401/403` and that `revokeProviderAccess` is never invoked, plus a positive test that the owning client can still revoke.
- **Severity adjudication note:** The Connect app-sec agent rated this High; the integration agent rated it Medium. Adjudicated **High** per the rubric ("exploitable cross-tenant authorization failure"), with the explicit caveat that the impact ceiling is availability and that current practical exploitability depends on ≥2 mutually-distrusting registered clients (today the registry may hold only one). It should be treated as High for a system explicitly built to be multi-tenant.

### AOC-02 — OAuth callback lacks broker-side browser-session binding (authorization-code injection if `broker_state` leaks)
- **Severity:** Medium · **Status:** Verified (design gap) · **Confidence:** Medium · **Applies:** local + production
- **Component / route:** Broker `GET /connect/:provider/start` and `/callback`.
- **Exact location:** `src/server.ts:156-199` (`/start` issues `res.redirect(302, redirectUrl)` and sets **no** cookie — confirmed by `grep` for `res.cookie`/`Set-Cookie` in `server.ts` returning nothing); `src/server.ts:201-233` (`/callback` verifies only the signed `broker_state`, then exchanges the query-supplied `code`).
- **Evidence (redacted):** The only browser binding in the whole flow is Showrunner's `connect_nonce` cookie (httpOnly, `SameSite=Lax`), set by Showrunner at its `/start` and checked only at redeem. The broker itself never ties the provider `code` to the browser that initiated the flow at the broker leg; it trusts the secrecy + single-use + 10-minute TTL of `broker_state`.
- **Attack prerequisites:** (1) Attacker obtains a **live, unconsumed** `broker_state` — it is exposed as the `state` query parameter in the victim's browser URL during the redirect to the provider (browser history, a malicious extension, shoulder-surfing, or client-side logging; note the broker sets `Referrer-Policy: no-referrer`, which blocks referrer leakage to the provider). (2) The victim's own flow has not yet consumed that state (they paused at the consent screen). (3) The attacker holds an unconsumed provider authorization `code` for the attacker's own merchant account issued against the broker's registered `redirect_uri` (obtainable by driving the provider's authorize step programmatically and reading the 302 `Location` without following it). (4) The attacker lures the still-logged-in victim admin to open a crafted callback URL within the TTL.
- **Concrete exploit scenario:** Victim starts connect → `broker_state` BS embedding nonce N. Attacker crafts `…/connect/stripe/callback?state=BS&code=<attacker's own code>` and gets the victim to open it while authenticated. The broker verifies BS, consumes the state, exchanges the attacker's code with **platform** creds (yielding the attacker's Stripe/Square tokens), seals a handoff **bound to nonce N** (from BS), and redirects the victim's browser to the victim's Showrunner callback with the opaque code. The victim's browser carries cookie N, so Showrunner redeems it (nonce matches) and stores the **attacker's** merchant account for the victim's site. The nonce check does **not** stop this because the attack reuses the victim's own `broker_state`.
- **Business/technical impact:** Payment redirection / merchant-of-record substitution for a single site (future charges settle to the attacker), plus a reliable DoS of the victim's connect attempt.
- **Remediation:** At `/start`, set a broker-owned cookie (`httpOnly`, `Secure`, `SameSite=Lax`, short maxAge, path `/connect`) carrying the `stateId` (or a hash of it); at `/callback`, require the cookie to match the `stateId` inside the verified `broker_state` **before** exchanging the code. This binds the provider code to the browser that started the flow at the broker, independent of Showrunner's nonce. (Optionally add PKCE per provider support.)
- **Recommended verification test:** With a captured live `broker_state`, replay the callback from a different cookie jar and confirm rejection once the cookie check exists (today it proceeds to token exchange). Negative-only in this audit — not exercised against production.

### AOC-03 — `main` unprotected + public repo + Railway auto-deploy
- **Severity:** Medium · **Status:** Verified · **Confidence:** High · **Applies:** production (CD integrity)
- **Component:** GitHub `Xarindar/AdmitOneConnect` → Railway production `connect`.
- **Exact evidence (verified):** `gh api repos/Xarindar/AdmitOneConnect/branches/main/protection` → `404 "Branch not protected"`; `gh repo view` → `visibility: PUBLIC`, `isPrivate: false`. `railway.json` uses the Dockerfile builder and `docs/SECURITY-OPERATIONS.md` states production deploys come from the `main` commit connected to Railway. CI (`security-ci`) runs `on: push: branches:[main]` — a **post-hoc** check, not a merge gate.
- **Attack prerequisites:** A compromised or over-scoped maintainer credential/token with push to `main` (the local `gh` token already carries `repo` + `workflow` scopes), or an erroneous/malicious direct push.
- **Concrete exploit scenario:** An actor with push access commits directly to `main`; Railway auto-builds and deploys to the production broker with no required review and no required status check. Malicious code would then hold the platform Stripe/Square secrets and every client shared secret in memory.
- **Impact:** Unreviewed single-actor path to full production compromise of a payment-OAuth broker; no enforced four-eyes control on a maximum-blast-radius service. The public repo also aids an attacker in crafting exploits (though it usefully enabled this audit).
- **Remediation:** Enable branch protection on `main`: require PR review, require `security-ci` to pass, block force-push/deletion, require linear history. Restrict Railway's deploy trigger to protected `main`. Reduce standing token scopes (drop `workflow` where unused); prefer short-lived/fine-grained tokens. Consider whether the repo needs to be public.
- **Recommended verification test:** `gh api …/branches/main/protection` returns 200 with `required_pull_request_reviews` and `required_status_checks` including `security-ci`; a direct push to `main` is rejected.

### AOC-04 — No provider-credential prefix/type validation (env-swap embeds platform secret in authorize URL)
- **Severity:** Medium · **Status:** Verified · **Confidence:** High · **Applies:** local + production
- **Component:** Broker `loadConfig`.
- **Exact location:** `src/lib/config.ts:36-39` (`requireEnv` only trims and checks non-empty — a `grep` for `startsWith`/`ca_`/`sk_`/`sq0idp`/`prefix` in `config.ts` returns nothing); consumed at `src/lib/providers.ts:83` (`url.searchParams.set("client_id", config.stripeConnectClientId)`) and `providers.ts:92` (Square).
- **Evidence (redacted):** If an operator pastes the platform secret key into `STRIPE_CONNECT_CLIENT_ID` (or swaps `SQUARE_APP_ID`/`SQUARE_APP_SECRET`), `buildStripeAuthorizeUrl` places that value as `client_id` in the 302 redirect to `connect.stripe.com` — exposing the secret in the browser address bar, history, provider access logs, and any intermediary.
- **Attack prerequisites:** A single deploy-time misconfiguration (swapped/mistyped env var). No attacker action required to cause the exposure; an attacker merely needs to observe one `/start`.
- **Concrete exploit scenario:** Swapped Stripe vars → the first `/start` emits the platform secret key in a browser-visible URL → platform-wide Stripe credential disclosure.
- **Impact:** Potential platform-wide Stripe/Square credential disclosure from one typo — very high blast radius, low probability. Fail-fast validation is a cheap, high-value guard.
- **Remediation:** In `loadConfig`, validate prefixes and fail fast: `STRIPE_CONNECT_CLIENT_ID` starts with `ca_`; `STRIPE_PLATFORM_SECRET_KEY` starts with `sk_` (optionally warn on `sk_test_` when a production flag is set); `SQUARE_APP_ID` starts with `sq0idp-` (or `sandbox-sq0idp-`). Reject on mismatch.
- **Recommended verification test:** Set `STRIPE_CONNECT_CLIENT_ID=sk_live_x` in a test config and assert the app refuses to start (today it boots and would leak on first `/start`).

### AOC-05 — Rate limiting is per-replica in-memory (not shared across the 2 production replicas)
- **Severity:** Low · **Status:** Verified · **Confidence:** High · **Applies:** production (2 replicas)
- **Location:** `src/lib/rate-limit.ts:11-40` (process-local `Map`), invoked in `src/server.ts:136,149,158,203,297,323,355`; `railway.json:16-20` (`numReplicas: 2`).
- **Evidence:** Counters live in one process; the live `/health` returned a per-instance `RateLimit-Remaining`. With 2 replicas behind the load balancer, effective throttles are ~2× the configured values and reset to zero on every redeploy/replica restart. Map cleanup only prunes already-expired entries and only when `size > 10_000`, so a many-IP flood can push the map past 10k live entries and run an O(n) sweep per request.
- **Impact:** Weaker-than-documented volumetric abuse/DoS throttling and provider-API cost protection. **Does not** weaken security-critical guarantees — one-time state, one-time handoff codes, and request-id replay all live in shared Postgres and hold cluster-wide.
- **Remediation:** Back rate-limit counters with shared storage (Postgres/Redis) keyed by client/IP so limits are global and survive restarts; bound map growth with an eviction cap, not just expiry pruning. Or explicitly document per-route limits as per-replica and size accordingly.
- **Verification test:** From one source, exceed a route's limit while replicas > 1; confirm 429 at the aggregate limit and persistence across a redeploy.
- **Related (unverified):** `app.set("trust proxy", 1)` (`server.ts:134`) is correct only if there is exactly one trusted proxy hop in production. Confirm Railway's edge topology; a mismatch could let clients influence `req.ip` and evade per-IP limits/logging. Not verifiable without authenticated Railway access.

### AOC-06 — Payment-credential encryption key falls back to `AUTH_SECRET` and uses raw SHA-256
- **Severity:** Low (defense-in-depth) · **Status:** Verified · **Confidence:** High · **Applies:** both
- **Location:** Showrunner `lib/payments/credential-crypto.ts:14-25`.
- **Evidence:** `credentialSecret()` = `PAYMENT_CREDENTIAL_ENCRYPTION_KEY || AUTH_SECRET || "local-dev…"`; `encryptionKey()` = `sha256(secret)` used directly as the AES-256-GCM key (AES-GCM itself is used correctly, random 12-byte IV per encryption). `isWeakProductionSecret` only rejects <32 chars and a few placeholder substrings, so a low-entropy 32-char secret passes. Unlike the broker's sealed tokens (`hkdfSync` with domain separation), the at-rest key has no HKDF/domain-separation or per-record salt.
- **Impact:** The same secret can protect both session-JWT signing and payment tokens at rest (blast-radius coupling if `AUTH_SECRET` leaks). Production requires a set, non-weak key, so this is hardening, not an open hole.
- **Remediation:** Require a dedicated `PAYMENT_CREDENTIAL_ENCRYPTION_KEY` (drop the `AUTH_SECRET` fallback) and derive the AES key via HKDF with a context label.
- **Verification test:** In a prod-like env with `PAYMENT_CREDENTIAL_ENCRYPTION_KEY` unset, confirm the app refuses to store credentials rather than silently using `AUTH_SECRET`.

### AOC-07 — Global admin identity + Host-header site resolution (latent cross-site in a multi-site deployment)
- **Severity:** Low (conditional) · **Status:** Partially verified · **Confidence:** Medium · **Applies:** both (conditional on multi-site)
- **Location:** Showrunner `AdminUser` model (`prisma/schema/core.prisma`, verified: no `siteId`/`tenantId` field), `lib/auth.ts:189-193` (`requireAdmin` checks role only), `lib/site.ts:31-38,79-91` (site resolved from `x-forwarded-host`/`host`).
- **Evidence:** The admin session payload is `{ userId }` only; `resolveCurrentSite()` maps `normalizeHostname(x-forwarded-host || host)` to a `SiteDomain` row. `siteId` is server-derived (good — never a body/query field), so there is **no classic IDOR**; tenant isolation rests on host routing plus a global admin identity.
- **Impact:** In a single Showrunner instance genuinely serving multiple sites, an admin of site A directing requests at site B's hostname (or injecting `X-Forwarded-Host` through a permissive proxy) resolves to site B and could operate its payment connections. **Largely latent** because the deployment model is one-site-per-deployment (`DEFAULT_SITE_ID`, `ClientDeployment`, per-client Showrunner deployments), which the audit confirmed is the norm.
- **Remediation:** Bind admin users to a tenant/site and assert membership in `requireAdmin`; select the tenant from a trusted host allow-list rather than trusting forwarded headers.
- **Verification test:** As an admin of site A, send a connect/disconnect request with `Host`/`X-Forwarded-Host` for site B; expect authorization failure.

### AOC-08 — No minimum length/entropy check on broker secrets
- **Severity:** Low · **Status:** Verified · **Confidence:** High · **Applies:** both
- **Location:** Broker `src/lib/config.ts:56-62` (`requireEnv` non-empty only), `src/lib/registry.ts:42-45` (client `secret` non-empty only).
- **Evidence:** `ADMITONE_CONNECT_SIGNING_SECRET` and each client `secret` are accepted at any non-empty length. A short/low-entropy signing secret weakens both the `broker_state` HMAC and the HKDF root for handoff AEAD; a weak client secret weakens client-state and service-request HMACs. (Showrunner enforces a ≥32-char check on its side for `AUTH_SECRET`/payment key; the broker has no equivalent.)
- **Impact:** Defense-in-depth; the setup docs instruct 32-byte random secrets, so this is a guardrail against operator error, not a live break.
- **Remediation:** Enforce a minimum length (e.g. ≥32 chars) on the signing secret and each client secret at load; fail fast otherwise.
- **Verification test:** Start with a 4-char signing secret and confirm the app refuses to boot.

### AOC-09 — CI omits container-image scanning, secret scanning, and SBOM; audit gate high-only
- **Severity:** Low (hardening) · **Status:** Verified · **Confidence:** High · **Applies:** both
- **Location:** `.github/workflows/security-ci.yml` (steps: `npm audit --audit-level=high`, `lint`, `test`, `build`, `docker build`).
- **Evidence:** No Trivy/Grype image scan, no gitleaks/secret scan, no SBOM. `--audit-level=high` passes on Moderate/Low advisories. The built image is never scanned; no automated guard against a future accidental secret commit (this audit found none today).
- **Impact:** A vulnerable base-image/OS package or a future committed secret could reach production undetected.
- **Remediation:** Add image vulnerability scanning on the built tag, a secret scanner on PRs, and optionally SBOM generation; keep `--audit-level=high` but periodically review Moderate.
- **Verification test:** CI shows a scan step producing SARIF; a benign known-vulnerable dep on a test branch fails the gate.

### AOC-10 — Stripe `read_write` hands off and stores the merchant's live secret key; relies on deprecated OAuth token fields
- **Severity:** Low · **Status:** Verified · **Confidence:** High · **Applies:** both
- **Location:** Broker `src/lib/providers.ts:84` (`scope=read_write`), `providers.ts:126-127` (requires `access_token`/`refresh_token`); Showrunner `lib/payments/connect/flow.ts:204,216-237` (`secretKey: accessToken`).
- **Evidence (doc-backed):** For Stripe Connect Standard OAuth the returned `access_token` **is** the connected account's `sk_live_…` key; Stripe's current OAuth reference marks `access_token`/`refresh_token` as *deprecated*, recommending the `Stripe-Account` header with the platform key instead (https://docs.stripe.com/connect/oauth-reference, https://docs.stripe.com/connect/oauth-standard-accounts). `read_write` is the only usable scope for a payments platform (`read_only` is extensions-only), so the breadth is inherent.
- **Impact:** A Showrunner DB compromise yields each merchant's full live secret key (maximal per-merchant blast radius), and future removal of the deprecated fields would break connect (`readString` throws). Mitigated at rest by `encryptGatewaySecret`.
- **Remediation (strategic):** Migrate to the `Stripe-Account` header model so the platform key is used per-request and no merchant key is stored; if retained, keep at-rest encryption and minimal retention. Treat Stripe `refresh_token` as optional (Standard tokens are non-expiring).
- **Verification test:** Confirm charges succeed via the `Stripe-Account` header without storing `access_token`.

### AOC-11 — Dead code `src/lib/signatures.ts` (weaker, body-only signature)
- **Severity:** Informational · **Status:** Verified · **Confidence:** High
- **Location:** `src/lib/signatures.ts` — `grep` for imports across `src/` and `test/` returns nothing; the live path is `request-auth.ts verifyServiceRequest`.
- **Why it matters:** `signRawBody`/`verifyRawBodySignature` sign only the raw body (no method/path/envelope binding). If reintroduced, they would reopen cross-endpoint replay. Recommend deleting to prevent regression. Not a live vulnerability.

### AOC-12 — Stripe `livemode` surfaced but not enforced by the broker
- **Severity:** Informational · **Status:** Verified · **Confidence:** High · **Applies:** production
- **Location:** `src/lib/providers.ts:130-132` (reads and passes `livemode`, no assertion); Showrunner `flow.ts:225` records `keyMode`.
- **Evidence:** Nothing rejects `livemode:false` in a production deployment. Stripe already rejects a test-mode code when an `sk_live` key is used, so this is defense-in-depth.
- **Remediation:** Optionally require `livemode===true` behind a production flag; at minimum document the invariant.

### AOC-13 — `request_id` generated at exactly the broker's minimum length
- **Severity:** Informational · **Status:** Verified · **Confidence:** High · **Applies:** both
- **Location:** Showrunner `lib/payments/connect/broker-client.ts:23` (`randomBytes(24).toString("base64url")` = 32 chars) vs broker `src/server.ts:456` (`^[A-Za-z0-9_-]{32,128}$`).
- **Evidence:** Entropy is ample (192 bits), but any future reduction of the byte count would silently fail the broker's validation. No current vulnerability.
- **Remediation:** Generate ≥32 bytes (well inside the range) or pin the length invariant with a comment/test.

### AOC-14 — Square authorize omits `redirect_uri` (relies on dashboard-registered URL)
- **Severity:** Informational · **Status:** Partially verified · **Confidence:** Medium · **Applies:** production
- **Location:** `src/lib/providers.ts:90-99` (no `redirect_uri` set, unlike Stripe at `providers.ts:85`).
- **Evidence (doc-backed):** Acceptable per Square (the redirect URL is registered in the Developer Console). But if multiple production redirect URLs are ever registered, routing is ambiguous, and there is no code-level assertion that the registered URL equals `{BROKER_PUBLIC_URL}/connect/square/callback` (https://developer.squareup.com/docs/oauth-api/create-urls-for-square-authorization).
- **Remediation:** Keep exactly one production redirect URL registered = the broker callback; optionally set `redirect_uri` explicitly to pin it.

### AOC-15 — Railway edge version headers + HSTS lacks `preload`
- **Severity:** Informational · **Status:** Verified · **Confidence:** High · **Applies:** production
- **Evidence (live):** Responses include `Server: railway-hikari`, `x-railway-request-id`, `x-railway-edge: atl1` — platform-injected (the app correctly disables `x-powered-by` at `server.ts:133`), so not app-fixable. `Strict-Transport-Security: max-age=31536000; includeSubDomains` has no `preload` and the host is not on the preload list.
- **Remediation:** Accept the edge headers as platform behavior. If the apex owner agrees, add `; preload` and submit `admitonedesign.com` to the HSTS preload list (requires apex-level coordination).

### AOC-16 — Plaintext env secrets, no KMS envelope (accepted architectural risk)
- **Severity:** Informational · **Status:** Verified · **Confidence:** High · **Applies:** production
- **Evidence:** All broker secrets load from env via `requireEnv`. A Railway env compromise = total system compromise (forge any token, act on every connected account). The single `ADMITONE_CONNECT_SIGNING_SECRET` protects both `broker_state` HMAC and handoff AEAD, but the AEAD key is HKDF-domain-separated by token type (`tokens.ts:174-184`), which correctly limits cross-use.
- **Remediation:** Where feasible, move platform secrets behind a secret manager/KMS with short-lived material; ensure the rotation runbook covers the signing secret, per-client secrets, and provider keys.

### AOC-17 — Framework 4xx error messages reflected
- **Severity:** Informational · **Status:** Verified · **Confidence:** Medium · **Applies:** both
- **Location:** `src/server.ts:388-398` error handler.
- **Evidence:** For status < 500 and a generic `Error` with a `.status` (e.g. body-parser JSON-parse `400` or `413` payload-too-large), the handler returns `error.message` verbatim. These are benign framework strings; `HttpError` messages are static and safe. This is the corrected residual of the disproved provider-disclosure claim (see §9).
- **Remediation:** Optional — map body-parser errors to fixed generic messages for consistency. No security impact.

## 9. Unverified concerns and false positives

**False positive — Provider `error_description` disclosure on refresh/revoke (raised by the Connect app-sec branch, B1-003).** Disproved during verification. The error handler maps every `ProviderExchangeError` to HTTP 502, and `message: status >= 500 ? "internal server error" : message` (`src/server.ts:395-398`) forces a generic body for all status ≥ 500. Therefore provider `error_description`/`errors[].detail` text is **never** returned to the client on `/connect/square/refresh` or `/revoke`. The only messages that reach a client are static `HttpError` strings, the fixed `TokenError` string, and generic framework 4xx messages (captured as AOC-17). No provider or secret text is disclosed.

**Unverified due to Railway CLI being unauthenticated (require an authenticated operator to confirm):**
- Exact linked project / environment / service ID; that only the intended service is deployed (no duplicate/unused services).
- Production **variable names present** and whether they are stored as sealed vs. plain Railway variables.
- **Cross-service secret isolation** — whether other services in the Railway project can reference Connect's variables.
- **Actual** runtime replica count and compute region (config declares 2× `us-west2`; the live edge header `atl1` reflects the nearest anycast edge to the prober, not the compute region).
- **Deployment drift** — whether the deployed image SHA matches current `main` (`578d5e4`).
- **Runtime logs** for error/PII/secret leakage (code-level redaction discipline is present and strong; live logs not inspectable).
- Railway member list, MFA, least-privilege production membership, and session state.

**Unverified due to no provider dashboard access:**
- Whether Stripe Connect is **Standard** (not Express) and the registered OAuth redirect URI equals `{BROKER_PUBLIC_URL}/connect/stripe/callback`.
- Whether `STRIPE_PLATFORM_SECRET_KEY` is actually `sk_live` and `SQUARE_OAUTH_ENV=production` live (config defaults to production).
- Whether `STRIPE_CONNECT_CLIENT_ID` is a valid `ca_…` and `SQUARE_APP_ID` a valid `sq0idp-…` (AOC-04 concerns the missing guard, not the actual values).
- Whether the Square app registers exactly the broker callback and only the five documented scopes; any Stripe restricted-key scoping on the platform key.

## 10. Railway deployment assessment

**Confirmed strengths:** `railway.json` matches the intended spec (2 replicas `us-west2`, `/health` check with 30 s timeout, `restartPolicyType ON_FAILURE` max 10, Dockerfile builder). The Dockerfile is well-hardened: pinned `node:24.18.0-alpine`, multi-stage, `npm ci --ignore-scripts` (blocks dependency lifecycle scripts), `npm prune --omit=dev`, `--chown=node:node`, `USER node` (non-root), `NODE_ENV=production`. `.dockerignore` keeps `.env`, `.git`, `.github`, `test`, `*.md`, and `plan.txt` out of the build context. `.env` is gitignored and untracked; `dist/` is gitignored. Live TLS is a valid Let's Encrypt certificate (TLS 1.3, `TLS_AES_256_GCM_SHA384`, CN `connect.admitonedesign.com`, valid through 2026-10-16) with HSTS. `/health` performs a real DB ping. Negative routes return minimal JSON with correct codes and no stack traces. CI on `main` is green with `GITHUB_TOKEN` restricted to `contents: read`.

**Confirmed gaps:** AOC-03 (unprotected public `main` + auto-deploy), AOC-05 (per-replica rate limiting), AOC-09 (CI scanning gaps), AOC-15 (edge headers / HSTS preload).

**Not verifiable (Railway CLI unauthenticated):** everything in §9's Railway list. **Recommendation:** an operator should authenticate the Railway CLI and confirm variable sealing, single-service isolation, replica/region, image-SHA-to-`main` parity, and log hygiene, and should verify least-privilege membership + MFA.

## 11. Showrunner integration assessment

**Contract verdict: byte-for-byte MATCH, no wire drift.** Verified on both sides and numerically: identical `base64url`; HMAC computed over the **ASCII** bytes of the encoded payload on both sides; the identical 10-field newline-joined canonical service request; `v1=`-prefixed 43-char signatures; `request_id` = 32 base64url chars (∈ the broker's `{32,128}`); service-request `exp=iat+300` exactly at the broker's `SERVICE_REQUEST_TTL_SECONDS`; client-state `exp=iat+600` at the broker max; identical length-hiding constant-time comparison. Sealed tokens (handoff, Square refresh) are only ever sealed/opened by the broker, so there is no client-side compatibility requirement.

**Verified positive controls:** `requireAdmin("settings:update")` on start/callback and the connect/disconnect/location-selection server actions; nonce cookie is httpOnly, `Secure` in production, `SameSite=Lax`, path-scoped, single-use (cleared on every callback outcome), and defeats handoff injection / OAuth merchant-confusion in the normal flow; handoff binding checks `typ`/`v`/`clientId`/`provider`/`siteId`/`nonce`; `siteId` is server-derived everywhere (no body-param IDOR); `locationId` is validated against stored `pendingLocations`; returnUrl/webhook URLs are built from env, not request headers (no open redirect/SSRF); compensation revokes provider access on any post-authorization failure on both sides; webhook handlers verify signatures (Stripe `constructEvent`; Square HMAC-SHA256 with a timing-safe, length-checked compare); merchant tokens are AES-256-GCM encrypted at rest.

**Integration-relevant findings:** AOC-01 (broker revoke gap, reached via Showrunner's `revokeOAuthProvider`), AOC-06 (credential key fallback), AOC-07 (global admin + host-derived site), AOC-13 (request_id min-length). **Lower-priority note:** Stripe/Square webhook verification tries *all* connected sites' secrets; in a multi-site deployment, downstream event handling should bind each event to the site owning the matched secret — latent under the one-site-per-deployment model, worth a targeted check.

## 12. Stripe and Square configuration assessment

**Stripe (Connect Standard OAuth) — correct and doc-backed.** `response_type=code` + `scope=read_write` against `connect.stripe.com/oauth/authorize`; `redirect_uri={BROKER_PUBLIC_URL}/connect/stripe/callback`; token exchange sends `client_secret` in the body; deauthorization uses Basic-auth secret key with `client_id`+`stripe_user_id` and verifies the echoed `stripe_user_id`. `read_write` is the only usable scope for a payments platform (breadth is inherent — AOC-10). `access_token`/`refresh_token` are Stripe-deprecated fields the broker still requires (AOC-10). `livemode` is surfaced but not enforced (AOC-12).

**Square (OAuth) — correct and doc-backed.** Production/sandbox base URLs selected by `SQUARE_OAUTH_ENV` (defaults to production); `session=false` set only in production (forces seller sign-in, recommended, unsupported in sandbox); scopes are least-privilege (`MERCHANT_PROFILE_READ PAYMENTS_READ PAYMENTS_WRITE ORDERS_READ ORDERS_WRITE` — no `PAYOUTS`/`BANK_ACCOUNTS`/`CUSTOMERS`); token exchange sends `client_id`+`client_secret` as JSON with a pinned `Square-Version`; revoke uses `Authorization: Client <secret>` with `client_id`+`merchant_id` and checks `success===true`; access-token ~30-day expiry handled by an off-path refresh with a 7-day buffer. Authorize omits `redirect_uri`, relying on dashboard registration (AOC-14).

**Production/sandbox isolation:** enforced by `SQUARE_OAUTH_ENV` and by Stripe key mode; the missing prefix validation (AOC-04) is the main config-safety gap. **Consent/account-selection:** Square `session=false` correctly forces explicit seller sign-in in production. **Docs consulted:** Stripe OAuth reference and Standard-accounts guide; Square OAuth overview, create-URLs, walkthrough, revoke-token, and authorize references.

## 13. Dependency and supply-chain assessment

**Broker:** `npm audit` → **0 vulnerabilities**. Minimal production surface: `dotenv@16.6.1`, `express@4.22.2`, `pg@8.21.0`. `npm ci --ignore-scripts` blocks dependency lifecycle-script execution in build and CI. Node engine pinned to `24.18.0` matching the Docker base and CI. No secrets in `package-lock.json` beyond integrity hashes.

**Showrunner:** far larger surface (Next.js, Prisma, AWS SDK, Stripe SDK, FullCalendar, etc.); a full audit of that tree is beyond the connect-integration scope, but no committed secrets were found in its history and the connect-relevant code is clean.

**Gaps:** no image/OS-package scanning, no automated secret scanning, no SBOM/integrity attestation in CI (AOC-09). A malicious transitive dependency in either service could exfiltrate in-memory secrets/tokens; the broker's small, pinned surface materially limits this.

## 14. Logging, monitoring, recovery, and rotation assessment

**Logging:** Strong discipline. The broker logs only `operation`/`provider`/`status`/`name` and returns generic 5xx bodies; no OAuth codes, URL queries, signatures, tokens, refresh handles, or registry values are logged (verified in `server.ts` and `docs/SECURITY-OPERATIONS.md`). Showrunner compensation logs error names + siteId only.

**Monitoring/recovery/rotation:** `docs/SECURITY-OPERATIONS.md` is a genuinely good runbook — it specifies release/rollback tied to the reviewed `main` commit and Railway deployment ID, a credential-incident order that **revokes merchant authorizations before rotating application credentials**, the correct rotation ordering (provider secrets → signing secret → per-client secrets → Showrunner `AUTH_SECRET`/`PAYMENT_CREDENTIAL_ENCRYPTION_KEY` with its decrypt/re-encrypt migration caveat), a quarterly provider lifecycle drill, and alerting on `/health`, 5xx/429, circuit openings, refresh staleness (>8 days), replica restart churn, and spend anomalies. **Gaps:** the runbook's controls are documented but their live enforcement (sealed variables, MFA, least-privilege membership, actual alert wiring) could not be verified without Railway access; and there is no visible automated per-client secret-rotation mechanism.

## 15. Prioritized remediation roadmap

**Immediate (this week):**
1. **AOC-03** — Enable branch protection on `main` (required review + `security-ci` status check + no force-push); restrict Railway deploy to protected `main`. Reduce standing token scopes.
2. **AOC-01** — Bind `/connect/:provider/revoke` to the caller (client-sealed revoke capability, or persisted `externalAccountId → clientId` map). This is the one High.
3. **AOC-04** — Add provider-credential prefix validation in `loadConfig` (fail-fast on `ca_`/`sk_`/`sq0idp-` mismatch).

**Within 7 days:**
4. **AOC-02** — Add a broker-owned httpOnly/Secure/SameSite state cookie set at `/start` and required to match at `/callback` before code exchange (optionally PKCE).
5. **AOC-06** — Require a dedicated `PAYMENT_CREDENTIAL_ENCRYPTION_KEY` (drop the `AUTH_SECRET` fallback) and derive via HKDF.
6. **Operator task** — Authenticate the Railway CLI and verify the §9/§10 unverified items (variable sealing, single-service isolation, replica/region, image-SHA parity, log hygiene, membership/MFA).

**Within 30 days:**
7. **AOC-05** — Move rate limiting to shared storage (Postgres/Redis) with bounded map growth; confirm the `trust proxy` hop count against Railway's edge.
8. **AOC-09** — Add image scanning + secret scanning (+ optionally SBOM) to CI.
9. **AOC-08** — Enforce minimum length on broker signing/client secrets at load.
10. **AOC-11** — Delete the dead `src/lib/signatures.ts`.

**Longer-term hardening:**
11. **AOC-10** — Evaluate migrating Stripe to the `Stripe-Account` header model to avoid storing merchant live keys; treat `refresh_token` as optional.
12. **AOC-07** — If multi-site-per-deployment is ever used, bind admin identity to a tenant and select the site from a trusted host allow-list; bind webhook events to the owning site.
13. **AOC-16** — Consider a secret manager/KMS envelope for platform secrets; formalize per-client secret rotation.
14. **AOC-12 / AOC-14 / AOC-15 / AOC-13 / AOC-17** — Address as informational polish.

## 16. Regression / security test plan

Add automated tests (extending `test/security.test.ts`, which already covers one-time state/handoff/request replay, cross-endpoint signature binding, and tokens-off-the-URL):
- **AOC-01:** client B (valid creds) cannot revoke client A's merchant → expect 401/403 and no provider call; owning client can.
- **AOC-02:** a captured live `broker_state` replayed from a different cookie jar is rejected once the state cookie exists; same-browser flow still succeeds.
- **AOC-04:** startup rejects a `client_id` var that fails the `ca_`/`sq0idp-` prefix; accepts a valid one.
- **AOC-06:** with `PAYMENT_CREDENTIAL_ENCRYPTION_KEY` unset in a prod-like env, credential storage refuses rather than falling back to `AUTH_SECRET`.
- **AOC-08:** startup rejects a too-short signing/client secret.
- **AOC-05:** aggregate 429 across replicas; map growth is bounded.
- **Contract guard:** a test pinning `request_id` length ≥ 32 and the byte-for-byte token/canonical formats between the two repos (prevents silent wire drift).
- **CI (AOC-09):** image scan and secret scan steps; a benign vulnerable dep on a branch fails the gate.
- **Live smoke (non-mutating):** the negative-route and TLS probes in §18, run on each deploy.

## 17. Residual risks

- **Broker env compromise = total compromise** (AOC-16). The broker concentrates all platform + client secrets; platform-level controls (Railway RBAC, MFA, sealed variables, rotation) are the only mitigation. Verify and harden them.
- **Compromised registered client** is contained to that client's own merchants **except** for the revocation cross-tenant reach (AOC-01, until fixed). No client can forge broker state or impersonate another client.
- **Merchant key storage** (AOC-10): a Showrunner DB compromise exposes that tenant's merchant Stripe live keys / Square tokens (encrypted at rest; strength depends on AOC-06).
- **AOC-02 code-injection** remains a real, if prerequisite-heavy, path until the broker binds the callback to the initiating browser.
- **Unverified Railway posture** (§9): until an operator confirms sealing/isolation/least-privilege, treat those as open questions rather than assurances.
- **Provider dashboard settings** (§9): registered redirect URIs, key modes, and scopes are assumed-correct from code but not independently confirmed.

## 18. Redacted verification appendix

All commands were read-only/non-destructive. No secret value appears below.

**Local build/test/audit (broker):**
- `npm run build` → exit 0. `npm run lint` (`tsc --noEmit`) → exit 0. `npm test` → 2/2 pass. `npm audit` → `found 0 vulnerabilities`. Production deps: `dotenv@16.6.1`, `express@4.22.2`, `pg@8.21.0`.

**Secret-exposure scan (values suppressed via redacting filter):** across all Git history of `AdmitOneConnect`, `showrunner`, and `admitone` — no real high-entropy Stripe/Square/generic keys. All prefix hits (`sk_live_`/`sk_test_`/`sq0idp-`/`ADMITONE_CONNECT_SIGNING_SECRET`) are documentation placeholders in `.env.example`/README/SETUP-KEYS/`config.ts` default/test. `.env` is untracked (only `.env.example`). Only 64-hex blob = a Docker image digest inside the prior audit doc.

**Live negative-route probes (`https://connect.admitonedesign.com`):**
- `GET /health` → `200 {"ok":true}`, full security-header set present.
- `GET /connect/stripe/start` (no params) → `400 {"error":"bad_request","message":"missing client_id"}`.
- `GET /connect/stripe/start?client_id=<nonexistent>` → `400 unknown client_id`.
- `GET /connect/bogus/start` → `404 {"error":"not_found","message":"unknown provider"}`.
- `GET /nope` → `404 route not found: GET /nope`.
- `GET /connect/stripe/callback` (no state) → `400 missing state`.
- `POST /connect/handoff/redeem` `{}` → `400 malformed handoff request` (body validated before auth).

**Live TLS:** issuer Let's Encrypt (CN=YE1), `TLSv1.3 TLS_AES_256_GCM_SHA384`, subject CN `connect.admitonedesign.com`, SAN correct, valid `Jul 18 2026 → Oct 16 2026`, HSTS `max-age=31536000; includeSubDomains`.

**CD integrity (verified):** `gh api …/branches/main/protection` → `404 "Branch not protected"`; repo `visibility: PUBLIC`; `security-ci` runs green on push (not a merge gate).

**Code confirmations (grep/read):** no ownership binding on `/revoke` (AOC-01); no cookie set anywhere in `server.ts` (AOC-02); no prefix validation in `config.ts` and `client_id` sourced from `config.stripeConnectClientId`/`squareAppId` into the authorize URL (AOC-04); `signatures.ts` imported nowhere (AOC-11); error handler forces generic message for status ≥ 500 (false-positive disproof); Showrunner `AdminUser` has no site/tenant field, `siteId` server-derived (AOC-07, no IDOR); contract numeric check — `request_id` 32 chars, opaque code 43 chars, envelope `exp−iat=300` within bound.

---

*Prepared by an automated multi-agent security audit with independent main-agent verification. Findings marked "Verified" were confirmed first-hand against source or live behavior. Items dependent on Railway/provider dashboard access are explicitly marked unverified and should be confirmed by an authenticated operator. This document contains no secret values.*
