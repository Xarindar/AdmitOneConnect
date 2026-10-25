import assert from "node:assert/strict";
import crypto from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { Pool } from "pg";
import { PostgresArtifactStore } from "../src/lib/artifact-store.js";

test("Postgres consumes handoffs once across replicas and removes expired payloads without a restart", {
  skip: !process.env.TEST_DATABASE_URL,
}, async (t) => {
  const admin = new Pool({ connectionString: process.env.TEST_DATABASE_URL });
  const schema = `connect_test_${crypto.randomBytes(8).toString("hex")}`;
  await admin.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(process.env.TEST_DATABASE_URL!);
  url.searchParams.set("options", `-c search_path=${schema}`);
  const pool = new Pool({ connectionString: url.toString() });
  const first = new PostgresArtifactStore(url.toString());
  const second = new PostgresArtifactStore(url.toString());
  t.mock.timers.enable({ apis: ["setInterval"] });
  try {
    await first.initialize();
    await second.initialize();
    const binding = { clientId: "client", siteId: "site", provider: "square" as const, nonce: "nonce" };
    await first.putHandoff("single-use", { ...binding, expiresAt: Math.floor(Date.now() / 1000) + 60, sealedPayload: "encrypted" });
    assert.equal(await second.consumeHandoff("single-use", { ...binding, siteId: "other" }), undefined);
    const redeemed = await Promise.all([first.consumeHandoff("single-use", binding), second.consumeHandoff("single-use", binding)]);
    assert.equal(redeemed.filter(Boolean).length, 1);
    await first.putHandoff("expired", { ...binding, expiresAt: 1, sealedPayload: "expired-credentials" });
    t.mock.timers.tick(60_000);
    let remaining = 1;
    for (let attempt = 0; attempt < 50 && remaining; attempt++) {
      await delay(10);
      remaining = Number((await pool.query("SELECT COUNT(*) AS count FROM admitone_connect_artifacts")).rows[0].count);
    }
    assert.equal(remaining, 0);
  } finally {
    await first.close();
    await second.close();
    t.mock.timers.reset();
    await pool.end();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  }
});
