# AdmitOne Connect

AdmitOne Connect is a small OAuth broker for Showrunner payment onboarding. It completes the one-time browser handshake and is never in the payment or token-refresh path. Stripe tokens are exchanged once and handed to Showrunner. Square uses end-to-end PKCE: Connect sees only the public challenge and short-lived authorization code, while Showrunner exchanges and refreshes its tokens directly with Square.

## Flow

1. Showrunner redirects the admin to `/connect/{provider}/start?client_id=...&state=...` on this broker.
2. The broker verifies the Showrunner-signed state token, checks that `returnUrl` belongs to the registered client origin, signs its own short-lived provider state, and redirects to Stripe or Square.
3. The provider redirects back to this broker with `code` and `state`.
4. For Stripe, the broker exchanges `code` once. For Square, it does not exchange the code; the signed client state must contain Showrunner's PKCE challenge.
5. The broker stores a short-lived sealed handoff and redirects to Showrunner with only a 256-bit opaque one-time code.
6. Showrunner redeems that code through an authenticated back-channel request. Stripe receives its token bundle; Square receives only the authorization code plus public exchange metadata.
7. Showrunner stores merchant tokens encrypted and calls both providers directly. Square token rotation is performed locally with PKCE.

Signed state tokens are HMAC-SHA256 compact tokens:

```text
base64url(JSON payload) + "." + base64url(HMAC_SHA256(encoded_payload, shared_secret))
```

Every token payload must include `typ`, `v`, `iat`, and an integer `exp`. Client state tokens use `typ: "admitone.client_state"`.

Broker database payloads use AES-256-GCM. Browser-facing handoff codes contain no payload and are single-use. Durable Postgres records make state, code, and service-request replay protection work across replicas.

## Environment

Copy `.env.example` to `.env` and fill in the values:

```bash
PORT=8080
DATABASE_URL=postgresql://...
PROVIDER_TIMEOUT_MS=10000
BROKER_PUBLIC_URL=https://connect.example.com
STRIPE_CONNECT_CLIENT_ID=ca_...
STRIPE_PLATFORM_SECRET_KEY=sk_live_...
SQUARE_APP_ID=sq0idp-...
SQUARE_OAUTH_ENV=production
ADMITONE_CONNECT_SIGNING_SECRET=long-random-broker-secret
ADMITONE_CONNECT_CLIENTS='{"client_1":{"secret":"long-random-shared-secret","returnOrigin":"https://showrunner.example.com"}}'
```

`ADMITONE_CONNECT_CLIENTS` is a JSON object keyed by the Showrunner client id. Each entry needs:

- `secret`: the shared HMAC secret also configured in that client's Showrunner deployment.
- `returnOrigin`: the exact HTTPS origin allowed for callbacks, with no path, query, or hash. `http://localhost` is allowed for local development only.

## Provider Setup

Stripe:

- Enable Connect on the platform account.
- Register `${BROKER_PUBLIC_URL}/connect/stripe/callback` as an OAuth redirect URI.
- Use a Standard Connect OAuth client id (`ca_...`) and the matching platform secret key.

Square:

- Create a Square Developer application.
- Register `${BROKER_PUBLIC_URL}/connect/square/callback` as the OAuth redirect URL.
- Use the production or sandbox application ID matching `SQUARE_OAUTH_ENV`. Connect does not need the Square application secret.
- Showrunner generates a PKCE verifier for each attempt and sends only its SHA-256 challenge in signed client state.
- By default the broker requests the documented `MERCHANT_PROFILE_READ PAYMENTS_READ PAYMENTS_WRITE ORDERS_READ ORDERS_WRITE` scopes. Override `SQUARE_OAUTH_SCOPES` only if the Showrunner integration changes.

## Authenticated endpoints

Showrunner redeems the one-time browser handoff through:

```http
POST /connect/handoff/redeem
Content-Type: application/json
X-AdmitOne-Signature: v1=<canonical-request HMAC-SHA256>

{"client_id":"client_1","site_id":"site_1","provider":"square","iat":1781900000,"exp":1781900300,"request_id":"random-unique-value","code":"<opaque-handoff>","nonce":"<browser-nonce>"}
```

The signature binds version, method, path, client, site, provider, issued/expiry times, request ID, and an exact body digest. The request ID and handoff are durably single-use.

Stripe OAuth disconnection may call `POST /connect/stripe/revoke`. Square PKCE credentials are disconnected locally; sellers can also revoke Admit One from their Square dashboard. There is no Square refresh endpoint.

## Development

```bash
npm install
npm run dev
npm run build
npm run lint
npm test
```

`GET /health` returns `{ "ok": true }`.
