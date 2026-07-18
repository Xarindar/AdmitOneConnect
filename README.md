# AdmitOne Connect

AdmitOne Connect is a small OAuth broker for Showrunner payment onboarding. It holds the platform-level Stripe Connect and Square OAuth credentials, completes the one-time OAuth handshake, then hands merchant tokens back to the client's own Showrunner deployment. It is not in the payment path.

## Flow

1. Showrunner redirects the admin to `/connect/{provider}/start?client_id=...&state=...` on this broker.
2. The broker verifies the Showrunner-signed state token, checks that `returnUrl` belongs to the registered client origin, signs its own short-lived provider state, and redirects to Stripe or Square.
3. The provider redirects back to this broker with `code` and `state`.
4. The broker exchanges `code` with the platform secret, seals a 5-minute encrypted `handoff` token with the client's shared secret, and redirects to the original Showrunner callback.
5. Showrunner opens the handoff and stores the merchant tokens encrypted in its own database. Square refresh tokens are returned as broker-sealed handles, not raw Square refresh tokens.

Signed state tokens are HMAC-SHA256 compact tokens:

```text
base64url(JSON payload) + "." + base64url(HMAC_SHA256(encoded_payload, shared_secret))
```

Every token payload must include `typ`, `v`, `iat`, and an integer `exp`. Client state tokens use `typ: "admitone.client_state"`.

Encrypted handoff and Square refresh-handle tokens use AES-256-GCM with keys derived from the same shared secret. Treat the token format as opaque and use the broker/client token helper implementation rather than parsing URL segments by hand.

## Environment

Copy `.env.example` to `.env` and fill in the values:

```bash
PORT=8080
BROKER_PUBLIC_URL=https://connect.example.com
STRIPE_CONNECT_CLIENT_ID=ca_...
STRIPE_PLATFORM_SECRET_KEY=sk_live_...
SQUARE_APP_ID=sq0idp-...
SQUARE_APP_SECRET=...
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
- Use production or sandbox app credentials matching `SQUARE_OAUTH_ENV`.
- By default the broker requests `MERCHANT_PROFILE_READ PAYMENTS_READ PAYMENTS_WRITE ORDERS_READ ORDERS_WRITE REFUNDS_READ REFUNDS_WRITE`. Override `SQUARE_OAUTH_SCOPES` only if the Showrunner integration changes.

## Square Refresh Endpoint

Showrunner refreshes Square tokens by calling:

```http
POST /connect/square/refresh
Content-Type: application/json
X-AdmitOne-Signature: <base64url HMAC-SHA256 over the exact raw JSON body>

{"client_id":"client_1","refreshToken":"<sealed-square-refresh-handle>","timestamp":1781900000,"nonce":"random-unique-value"}
```

`timestamp` is Unix time in seconds and must be within five minutes of broker time. `nonce` must be unique per client for that freshness window. The response returns a new sealed Square refresh handle in `refreshToken`.

The response is:

```json
{
  "accessToken": "...",
  "refreshToken": "...",
  "expiresAt": "2026-07-19T00:00:00Z"
}
```

## Development

```bash
npm install
npm run dev
npm run build
npm run lint
```

`GET /health` returns `{ "ok": true }`.
