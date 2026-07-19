# CLAUDE working findings log — Admit One Connect security audit

> Live scratchpad for the main-agent audit. Values are always redacted. This is NOT
> the final deliverable (that is SECURITY-AUDIT.md). Findings here are refined as
> sub-agents report and are independently verified before promotion.

Date: 2026-07-18. Auditor: main agent + 4 branch sub-agents.

**STATUS: COMPLETE.** Final deliverable written to SECURITY-AUDIT.md (18 sections). All 4 branch agents reported and were reconciled/verified. 1 High (AOC-01 revoke cross-tenant), 2 Medium (AOC-03 unprotected public main, AOC-04 no cred prefix validation), 6 Low, 7 Info, 1 resolved/stale finding (AOC-02 browser binding), and 1 false positive (provider-error disclosure). No Critical, no committed secrets, 0 dep advisories. NOTE: prior SECURITY-AUDIT.md audited a PRE-remediation build; its browser-handoff High + non-atomic replay + single replica + Node20 are all FIXED on current main (re-verified). Railway CLI unauth = live Railway inspection unverified (documented).

## Established ground truth (first-hand reads)

### Repos
- Connect broker: `C:\Users\Abe Tannenbaum\Documents\AdmitOneConnect` (github Xarindar/AdmitOneConnect, public).
- Showrunner: `Xarindar/showrunner` (public) — Next.js/Prisma. Cloned to scratchpad/showrunner.
- `Xarindar/admitone` (public) = marketing/studio static site. OUT OF SCOPE.

### Tooling status
- Railway CLI: **UNAUTHENTICATED** (`railway whoami` → Unauthorized). `railway login` is interactive; not triggered.
  => Branch 2 live Railway inspection is limited to repo config + external probing. METHODOLOGY LIMITATION.
- gh CLI: authenticated as Xarindar (repo, workflow, read:org scopes).
- Live broker https://connect.admitonedesign.com/health → 200, `Server: railway-hikari`, edge atl1. Security headers present & match code.

### Secret exposure scan (values suppressed)
- AdmitOneConnect: `.env` NOT tracked (only `.env.example`). Real-key regex scan across ALL history = EMPTY. Prefix hits (sk_live_/sk_test_/sq0idp-/SIGNING_SECRET) are all doc placeholders in `.env.example`, README, SETUP-KEYS, config default, test. Only 64-hex blob = docker image digest in prior SECURITY-AUDIT.md. => No committed secrets.
- showrunner + admitone: real-key scan = EMPTY. => No committed secrets.

### Connect architecture (broker, Express/TS, Node 24, Postgres store)
- Routes (src/server.ts): GET /health; GET /connect/:provider/start; GET /connect/:provider/callback; POST /connect/handoff/redeem; POST /connect/square/refresh; POST /connect/:provider/revoke.
- Token crypto (src/lib/tokens.ts): signed = base64url(JSON)."."base64url(HMAC-SHA256(secret, enc)); sealed = AES-256-GCM with HKDF-derived per-type key + AAD=tokenType. verify() timing-safe + typ + exp checks.
- Service request auth (src/lib/request-auth.ts): HMAC over canonical(method,path,client_id,site_id,provider,iat,exp,request_id,sha256(rawBody)); durable single-use via store.registerRequest.
- Replay protection durable in Postgres (artifact-store.ts): registerState/consumeState (one-time), registerRequest (one-time), putHandoff/consumeHandoff (one-time, bound to clientId+siteId+provider+nonce_digest). All SQL parameterized.
- Registry (registry.ts): env JSON {clientId:{secret,returnOrigin}}. returnOrigin normalized HTTPS origin.
- Return URL guard (server.ts assertAllowedReturnUrl): origin must === registered origin, no user/pass. Open-redirect mitigated.
- Rate limit (rate-limit.ts): in-memory per-process token buckets per route+IP. trust proxy=1.
- Provider calls (providers.ts): Stripe connect.stripe.com/oauth/{authorize,token,deauthorize}; Square connect.squareup[sandbox].com/oauth2/{authorize,token,revoke}. AbortSignal timeout. ProviderCallGuard = concurrency(20)+circuit breaker.
- Headers: HSTS, CSP default-src none, frame-ancestors none, nosniff, frame-deny, no-store, referrer no-referrer, permissions-policy locked, x-powered-by off.

### Showrunner integration (lib/payments/connect/*)
- tokens.ts: signConnectToken/verifyConnectToken/signServiceRequest — BYTE-FOR-BYTE match to broker. timing-safe compare present.
- flow.ts: createConnectStart (requireAdmin settings:update; nonce=16B hex; signed clientState + signed httpOnly nonce cookie sameSite=lax path=/api/payments/connect secure in prod). completeConnectHandoff verifies nonce cookie, redeems via authenticated back-channel, checks typ/v/clientId/provider/siteId/nonce.
- broker-client.ts: brokerRequest signs envelope; exp=iat+300 (== broker max, OK). revokeOAuthProvider passes externalAccountId.
- credential-crypto.ts: AES-256-GCM at rest; key=sha256(PAYMENT_CREDENTIAL_ENCRYPTION_KEY || AUTH_SECRET). Prod throws on weak/short key. **Key fallback to AUTH_SECRET = key-reuse concern.**
- Storage: prisma paymentGatewayCredential; Square access+refresh encrypted; Stripe access token stored as merchant secret key (Stripe Connect Standard OAuth).

## PRELIMINARY findings (unverified until checked) — redacted

| ID | Sev(prelim) | Component | Summary | Status |
|----|------|-----------|---------|--------|
| F-01 | Medium | Connect /revoke | Cross-tenant revocation: externalAccountId not bound to caller's client → a registered client can deauthorize another tenant's merchant (DoS). server.ts:353-367 | to-verify |
| F-02 | Low | Connect config | No min-length/entropy check on ADMITONE_CONNECT_SIGNING_SECRET or client secrets (config.ts requireEnv, registry.ts) | to-verify |
| F-03 | Low/Info | Showrunner crypto | PAYMENT_CREDENTIAL_ENCRYPTION_KEY falls back to AUTH_SECRET (key reuse across auth + payment-at-rest) credential-crypto.ts:15 | to-verify |
| F-04 | Low | Connect DoS | In-memory rate limiter is per-replica (2 replicas) & not shared; trust proxy=1 correctness on Railway. Defense-in-depth only (durable replay in PG) | to-verify |
| F-05 | Info | Connect Stripe | Stripe OAuth scope hardcoded read_write (broad; Stripe only offers read_only/read_write) providers.ts:84 | to-verify |
| F-06 | Info | Connect errors | Provider error_description surfaced in 502 message to authenticated client (refresh/revoke) | to-verify |
| F-07 | Info | Railway | CLI unauthenticated → cannot verify env-var isolation / service boundaries directly. Limitation. | noted |

## Strong positive controls observed (for the report)
One-time PG-backed state/handoff/request; opaque 256-bit browser codes; AES-GCM sealing with per-type HKDF keys + AAD; timing-safe HMAC everywhere; strict return-origin allowlist; provider-binding on every token; nonce/browser binding; circuit breaker + concurrency cap + request-size cap + socket timeouts; non-root minimal Docker image; parameterized SQL; locked-down security headers; CI runs audit+lint+test+build.

## Trust model (CONFIRMED)
- Broker = SHARED MULTI-TENANT: one Stripe platform account + one Square app, N registered clients (ADMITONE_CONNECT_CLIENTS). All tenants' merchants connect under the same platform creds.
- Each Showrunner deployment = SINGLE-TENANT (one client id, default site "site"; requireAdmin is deployment-global; siteId resolved from request hostname via siteDomain, NOT from request body). Multi-client = multiple separate Showrunner deployments.
- => Cross-tenant attack surface concentrates at the BROKER. A malicious/compromised registered client can reach other clients ONLY through broker routes that are not client-bound. Only /revoke is unbound (F-01). handoff/redeem + square/refresh are fully client+site+nonce bound.
- => Blast radius of a single compromised Showrunner deployment = that client's own merchants, PLUS (via F-01) the ability to revoke other clients' merchant grants (availability only).

## Verification results (main agent, independent)
- [x] clean build: `npm run build` exit 0
- [x] typecheck/lint: `npm run lint` (tsc --noEmit) exit 0
- [x] tests: `npm test` 2/2 pass
- [x] dependency audit: `npm audit` => 0 vulnerabilities. Prod deps: dotenv@16.6.1, express@4.22.2, pg@8.21.0.
- [x] live negative probes (all match code): /connect/stripe/start no params→400 "missing client_id"; /connect/bogus/start→404 "unknown provider"; /nope→404 "route not found: GET /nope"; /connect/stripe/callback no state→400 "missing state"; POST /connect/handoff/redeem {}→400 "malformed handoff request" (body validated before auth).
- [x] live TLS: Let's Encrypt (CN=YE1), TLSv1.3 TLS_AES_256_GCM_SHA384, CN=connect.admitonedesign.com, valid Jul 18–Oct 16 2026, HSTS present.
- [x] F-01 CONFIRMED: broker keeps NO merchant→client ownership map (grep). revoke handler (server.ts:353-367) takes body.externalAccountId from authenticated caller and calls provider deauthorize with the shared platform creds. Any registered client can revoke any tenant's merchant grant. Severity Medium (availability/DoS; needs registered-client secret + known account id; rises toward High in mutually-distrusting multi-tenant use).
- [x] Showrunner siteId server-derived: start=getCurrentSiteId(); callback=resolveCurrentSite().id; location-select + disconnect action use server site.id. siteId comes from hostname→siteDomain, never request body. No body-param IDOR in the connect flow.
- [x] Contract drift: NONE found so far — tokens.ts, request-auth.ts canonical, base64url, ascii-HMAC, envelope exp=iat+300 (== broker max SERVICE_REQUEST_TTL 300), request_id randomBytes(24).base64url=32 chars (∈ broker regex {32,128}). Awaiting Branch 3 agent confirmation.

## Branch 2 (Railway) agent results — reconciled
- B2-01 (Medium, VERIFIED by me): `main` unprotected (gh api → 404 "Branch not protected"), repo PUBLIC (isPrivate:false), Railway auto-deploys `main`, CI is post-push not a merge gate. CD-integrity gap. => maps to new finding F-08.
- B2-02 (Low, VERIFIED) = my F-04: in-memory per-replica rate limit (2 replicas → ~2x, resets on redeploy). Live /health showed per-instance counter. Durable replay unaffected (PG).
- B2-03 (Low, plausible): CI lacks image scan / secret scan / SBOM; `npm audit --audit-level=high` only. => F-09.
- B2-04 (Info, VERIFIED live): Railway edge headers (Server: railway-hikari, x-railway-*) — platform-injected, app disables x-powered-by. Not app-fixable. => Info.
- B2-05 (Info, VERIFIED live): HSTS lacks `preload`. => Info hardening.
- UNVERIFIABLE (Railway CLI unauth): linked project/env/service id, prod var names/sealing, cross-service secret isolation, actual replica/region, deploy drift vs main (578d5e4), runtime logs, member list/MFA/least-privilege. Documented as limitation.
- Positive controls confirmed: no committed secrets; .dockerignore excludes .env/.git/test; non-root pinned multi-stage image w/ --ignore-scripts + prune; railway.json matches spec; strong live headers; valid LE TLS; redacted logging discipline; server timeouts + 32kb body cap; CI GITHUB_TOKEN contents:read.
- Showrunner webhooks: Stripe verifies stripe-signature (constructPaymentWebhookEvent); Square verifies x-square-hmacsha256-signature. Both present (spot-checked).

## Branch 1 (Connect app-sec) agent results — reconciled
- B1-001 = F-01 cross-tenant revoke. Agent rated HIGH; I concur on HIGH (rubric: "exploitable cross-tenant authorization failure" = High). Impact ceiling = availability (sever another tenant's merchant), not data theft/takeover (so not Critical). Prereq: registered/compromised client + known account id. VERIFIED by me. Remediation: seal a per-merchant client-bound revoke capability at handoff time (mirror square-refresh handle) OR persist client_id→externalAccountId map and enforce.
- B1-002 = F-04 per-replica rate limit (Low). Confirmed. Also flags trust proxy=1 correctness (needs Railway edge-hop confirmation; unverifiable via CLI). Note: map cleanup only prunes expired entries when size>10k → O(n) sweep under many-IP flood (minor).
- B1-003 provider-error disclosure: **FALSE POSITIVE (my independent check).** ProviderExchangeError→502, and handler forces `message = "internal server error"` when status>=500 (server.ts:395-398 re-read). So provider error_description is NEVER returned to the client on refresh/revoke. Residual: only framework 4xx messages (body-parser JSON-parse/413) and static HttpError strings reach the client → Informational, no security impact. Downgrade F-06 to Info/false-positive.
- B1-004 = dead code: `src/lib/signatures.ts` (signRawBody/verifyRawBodySignature) imported NOWHERE (grep in src+test empty). VERIFIED. Info — recommend deletion to prevent regression to a body-only (unbound) signature. => F-10.
- Agent's 7 focus-question verdicts match my reads: replay/binding sound; no timing-unsafe compare; no missing exp; no return-URL open redirect; no secret in logs/errors/browser; DoS controls solid; deps clean (0 advisories, 127 deps). registerRequest runs only AFTER signature verify (server.ts:442) → unauth callers cannot pre-burn victim request-ids (good).

## Branch 3 (Showrunner integration) agent results — reconciled
- Contract verdict: **MATCH, no wire drift** (agent + my numeric check agree): base64url, ascii-HMAC, 10-field canonical, request_id 32 chars ∈ {32,128}, TTLs at boundary, timing-safe compare identical. Sealed tokens only broker-side.
- B3-01 = F-01 revoke gap. Agent rated MEDIUM (Branch 1 rated HIGH). ADJUDICATION: I set **High** per rubric ("exploitable cross-tenant authorization failure"=High), with explicit caveat that impact ceiling = availability and current real-world exploitability needs ≥2 mutually-distrusting registered clients (today likely 1). Both agents confirm the mechanism. Record the Med/High split in "conflicting evidence".
- B3-02 (NEW, Low, conditional): Showrunner admin identity is GLOBAL (AdminUser has no siteId/tenantId — VERIFIED via prisma core.prisma; session payload = {userId}; role only). Site resolved from x-forwarded-host/host (lib/site.ts). => in a multi-SITE single deployment, an admin could act cross-site via Host routing; siteId is still server-derived (not body param) so no classic IDOR. LATENT because deployment model = one site per deployment (DEFAULT_SITE_ID, ClientDeployment). Concrete hardening: don't trust forwarded Host for tenant selection; bind admin→tenant. => F-11 (Low, conditional).
- B3-03 = F-03 credential key: fallback to AUTH_SECRET + raw sha256 (no HKDF/salt); isWeakProductionSecret only rejects <32 chars/placeholders. Low hardening. Prod requires a set key. VERIFIED earlier by me.
- B3-04 (Info) = request_id at exact 32-char minimum (brittle coupling, ample entropy). => F-12 Info.
- Lower-priority note (Showrunner-core, tangential): Stripe/Square webhook verification tries ALL connected sites' secrets; must bind matched event to owning site to avoid cross-tenant event application in a multi-site deploy. Latent under single-site model. Note only.
- Positive controls verified by agent (match mine): nonce cookie httpOnly/secure/lax/path-scoped/single-use defeats handoff injection + OAuth merchant-confusion; one-time atomic DELETE...RETURNING; returnUrl origin-pinned (no open redirect/SSRF); Square handle sealed+tenant-bound; compensation/rollback both sides; webhooks signature-verified (Stripe constructEvent, Square HMAC timing-safe); siteId server-derived everywhere; locationId validated against stored pendingLocations.

## Branch 4 (provider config + threat model) agent results — reconciled
- Provider config verdict: correct & doc-backed. Stripe authorize/token/deauthorize all match docs (deauthorize verifies echoed stripe_user_id). Square prod/sandbox base URLs, session=false in prod only, scopes least-privilege (no PAYOUTS/BANK/CUSTOMERS), revoke Authorization: Client scheme, Square-Version header — all correct.
- B4-01 / AOC-02 (**RESOLVED/STALE**): the broker already calls `setBrokerStateCookie(...)` during `/start`, then requires `hasValidBrokerStateCookie(...)` before exchanging the provider code in `/callback`. The provider-scoped, httpOnly, Secure/SameSite browser-binding cookie closes the authorization-code injection path described in the preliminary finding. Removed from the active finding count and final list.
- B4-02 (Medium, Verified): config.ts requireEnv has NO prefix/type check (CONFIRMED). Swapping STRIPE_CONNECT_CLIENT_ID with the sk_live key → sk placed as client_id in browser-facing authorize 302 → platform secret disclosure. Contingent on operator misconfig; high impact-if-triggered. Fix: validate ca_/sk_/sq0idp- prefixes, fail fast. => AOC-04.
- B4-03/B4-05 (Low): Stripe read_write hands off & stores merchant live secret key; relies on deprecated access_token/refresh_token OAuth fields (Stripe still returns them). Forward-compat + blast-radius. => AOC-10.
- B4-04 (Low/Info): livemode surfaced, not enforced (test key in prod → non-chargeable "connected" state). Note: sk_live already rejects test codes (defense-in-depth). => AOC-12.
- B4-06 (Low/Info): plaintext env secrets, no KMS; single signing secret for HMAC + AEAD but HKDF-domain-separated (good). => AOC-16.
- B4-07 (Info): Square authorize omits redirect_uri (relies on dashboard registration). => AOC-14.
- Threat model complete (9 actors). Live negative tests re-confirmed (incl. unknown client_id → 400). Docs cited: Stripe OAuth reference/standard-accounts; Square OAuth overview/create-urls/walkthrough/revoke-token/authorize.
- UNVERIFIABLE w/o dashboards: Stripe Standard vs Express, registered redirect URIs, actual live key modes, scope registration, restricted keys.

## FINAL consolidated finding IDs (for report)
AOC-01 High (revoke cross-tenant) · AOC-03 Med (main unprotected+public+auto-deploy) · AOC-04 Med (no cred prefix validation) · AOC-05 Low (per-replica rate limit) · AOC-06 Low (payment key AUTH_SECRET fallback/no HKDF) · AOC-07 Low cond (global admin + host-header site) · AOC-08 Low (no broker secret min-length) · AOC-09 Low (CI no image/secret scan/SBOM) · AOC-10 Low (Stripe read_write stores merchant key/deprecated fields) · AOC-11 Info (dead signatures.ts) · AOC-12 Info (livemode not enforced) · AOC-13 Info (request_id min-length brittle) · AOC-14 Info (Square redirect_uri omitted) · AOC-15 Info (edge headers/HSTS no preload) · AOC-16 Info (plaintext env secrets) · AOC-17 Info (framework 4xx message reflection).
RESOLVED/STALE: AOC-02 browser-binding/code-injection (broker cookie is set and validated).
FALSE POSITIVE: B1-003 provider-error-text disclosure (ProviderExchangeError→502→generic).
Severity adjudication AOC-01: Branch1=High, Branch3=Med → HIGH (rubric: exploitable cross-tenant authz failure), impact ceiling=availability.

## Refined severity note for F-01
Cross-tenant authorization failure but impact limited to revocation/disconnect (availability), not data theft/takeover, and requires an already-registered client credential plus a known target account id (merchant ids are semi-public). => High under the adopted rubric; the impact ceiling and prerequisites constrain blast radius but do not change the canonical severity.
