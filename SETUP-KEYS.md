# SETUP-KEYS — every key and token you need to insert

Two places take keys: **this broker's `.env`** (holds your platform-level secrets, deployed once by
you) and **each client Showrunner deployment's env** (three vars that point it at this broker).
No provider keys ever go in a client deployment.

Fill things in the order below. ▢ = you do it once, per the label.

---

## 1. Generate your random secrets first

Run this once per secret you need (any machine with Node):

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

You need one **broker signing secret** plus one **shared secret per client deployment**.

---

## 2. Broker `.env` (this repo — copy `.env.example` to `.env`)

| Key | Paste in | Where you get it |
|---|---|---|
| `PORT` | `8080` (or your host's port) | — |
| `BROKER_PUBLIC_URL` | ▢ the public HTTPS URL you deploy this broker at, **no trailing slash** (e.g. `https://connect.cosmicevents.net`) | your hosting setup |
| `STRIPE_CONNECT_CLIENT_ID` | ▢ starts with `ca_` | Stripe Dashboard → **Settings → Connect → Onboarding options → OAuth** (enable Connect first, see §3) |
| `STRIPE_PLATFORM_SECRET_KEY` | ▢ starts with `sk_live_` (or `sk_test_` while testing) | Stripe Dashboard → **Developers → API keys** on YOUR platform account |
| `SQUARE_APP_ID` | ▢ starts with `sq0idp-` | Square Developer dashboard → your app → **Credentials** (Production) |
| `SQUARE_APP_SECRET` | ▢ | same screen as the app id (click Show) |
| `SQUARE_OAUTH_ENV` | `production` (or `sandbox` while testing) | — |
| `SQUARE_API_VERSION` | leave the default | — |
| `SQUARE_OAUTH_SCOPES` | leave blank (defaults cover Showrunner) | — |
| `ADMITONE_CONNECT_SIGNING_SECRET` | ▢ one generated random secret (§1) | you generate it |
| `ADMITONE_CONNECT_CLIENTS` | ▢ JSON registry, one entry per client — see below | you write it |

**`ADMITONE_CONNECT_CLIENTS` format** (single line of JSON; `returnOrigin` is the client site's
origin only — no path, no trailing slash):

```json
{"acme":{"secret":"<that client's generated shared secret>","returnOrigin":"https://acme-events.com"},"blue":{"secret":"<another generated secret>","returnOrigin":"https://blue-weddings.com"}}
```

---

## 3. One-time provider dashboard setup (your accounts)

**Stripe (once):**
- ▢ Enable **Connect** on your Stripe platform account (Dashboard → Connect → Get started; choose **Standard** accounts).
- ▢ Register the OAuth redirect URI: `{BROKER_PUBLIC_URL}/connect/stripe/callback`
  (Settings → Connect → Onboarding options → OAuth → Redirects).
- ▢ Copy the **OAuth client ID** (`ca_…`) from that same OAuth page → `STRIPE_CONNECT_CLIENT_ID`.

**Square (once):**
- ▢ Create an application at https://developer.squareup.com/apps.
- ▢ Under **OAuth**, set the Production Redirect URL to: `{BROKER_PUBLIC_URL}/connect/square/callback`
- ▢ Copy the **Application ID** and **Application Secret** → `SQUARE_APP_ID` / `SQUARE_APP_SECRET`.

**Square webhooks (once per client, optional but recommended):** Square webhook subscriptions are
app-level, so the client can't create them via OAuth. In the Square Developer dashboard → your app →
**Webhooks → Subscriptions**, add one subscription per client site pointing at
`https://<client-site>/api/webhooks/square` with events `payment.updated` and `refund.updated`, then
give that subscription's **Signature key** to the client to paste in
Payments → Square → Manage → "Save webhook key". (Stripe needs nothing here — the client's webhook is
created automatically during one-click connect.)

---

## 4. Each client Showrunner deployment (three env vars)

| Key | Paste in |
|---|---|
| `ADMITONE_CONNECT_BASE_URL` | ▢ same value as the broker's `BROKER_PUBLIC_URL` |
| `ADMITONE_CONNECT_CLIENT_ID` | ▢ that client's key in `ADMITONE_CONNECT_CLIENTS` (e.g. `acme`) |
| `ADMITONE_CONNECT_SHARED_SECRET` | ▢ that client's `secret` from the registry — must match exactly |

If all three are blank the client falls back to the old paste-your-own-keys wizard, so rolling this
out is safe per client.

---

## 5. Checklist to go live

1. ▢ Generate secrets (§1) and fill the broker `.env` (§2).
2. ▢ Do the Stripe + Square dashboard setup (§3).
3. ▢ Deploy this broker; check `GET {BROKER_PUBLIC_URL}/health` returns `{"ok":true}`.
4. ▢ Add each client to `ADMITONE_CONNECT_CLIENTS` and set the three client vars (§4); redeploy both.
5. ▢ In the client's admin → Payments, click **Connect** on Stripe — you should land on Stripe's
   hosted login and bounce back to Payments with "Stripe is connected."
6. ▢ Same for Square, then paste the Square webhook signature key (§3) under Manage.
7. ▢ (Square only) schedule `npm run payments:refresh-square` daily on each client deployment so
   Square's ~30-day tokens refresh well ahead of expiry.
