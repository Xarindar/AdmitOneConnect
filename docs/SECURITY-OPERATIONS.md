# Security operations runbook

## Release and rollback

Production deploys must come from the reviewed `main` commit connected to Railway. CI must pass the typecheck, security tests, dependency audit, build, and minimal-image build before merge. Record the Git SHA and Railway deployment ID in the change ticket.

Verify `/health`, then exercise signed synthetic start/replay/redeem tests without completing real provider consent. On failure, roll Railway back to the last healthy deployment and verify both Connect and Showrunner. Never roll back only one side across a protocol-version change.

## Credential incident and rotation order

1. Restrict production access, revoke suspicious Railway sessions, preserve redacted logs, and identify affected clients/providers without printing secret values.
2. Revoke affected merchant authorizations through Stripe/Square before rotating application credentials when bearer-token disclosure is possible.
3. Rotate provider application secrets in their dashboards, update sealed Railway variables, and verify sandbox/synthetic exchange.
4. Rotate `ADMITONE_CONNECT_SIGNING_SECRET`; outstanding state/handoff records will become unusable.
5. Rotate each client shared secret on Connect and its matching Showrunner deployment in one change window.
6. Rotate Showrunner `AUTH_SECRET`, worker/webhook secrets, and database credentials according to their own runbooks.
7. `PAYMENT_CREDENTIAL_ENCRYPTION_KEY` requires a decrypt/re-encrypt migration; never replace it without migrating every credential first.
8. Rebuild both services from reviewed commits, validate health and provider lifecycle, then invalidate old Railway/provider sessions.

Do not copy secrets into tickets, chat, shell history, or logs. Use sealed Railway variables where the runtime does not need CLI retrieval, project-scoped automation credentials, MFA, and least-privilege production membership.

## Provider lifecycle drill

Quarterly in sandbox: connect, replay the callback concurrently, redeem twice, inject webhook/database failure, verify compensation, disconnect, and confirm upstream revocation plus webhook deletion. For Square, confirm explicit location selection, daily refresh execution, and an alert when the last successful refresh exceeds eight days.

## Monitoring

Alert on `/health` failure, HTTP 5xx/429 rates, provider circuit openings/timeouts, failed compensation/revocation, Square refresh failures/staleness, deployment failure, replica restart churn, database capacity, and spend anomalies. Logs must contain operation/provider/status/request IDs only—never OAuth codes, URL queries, signatures, access tokens, refresh handles, registry values, or raw provider responses.
