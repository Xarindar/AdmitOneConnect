import crypto from "node:crypto";
import { Pool } from "pg";
import type { Provider } from "./providers.js";

export interface HandoffRecord {
  clientId: string;
  siteId: string;
  provider: Provider;
  nonce: string;
  sealedPayload: string;
  expiresAt: number;
}

export interface ArtifactStore {
  initialize(): Promise<void>;
  close(): Promise<void>;
  ping(): Promise<void>;
  registerState(id: string, expiresAt: number): Promise<boolean>;
  consumeState(id: string): Promise<boolean>;
  registerRequest(clientId: string, requestId: string, expiresAt: number): Promise<boolean>;
  putHandoff(code: string, record: HandoffRecord): Promise<void>;
  consumeHandoff(
    code: string,
    expected: Pick<HandoffRecord, "clientId" | "siteId" | "provider" | "nonce">,
  ): Promise<HandoffRecord | undefined>;
}

type MemoryEntry = {
  kind: "state" | "request" | "handoff";
  expiresAt: number;
  handoff?: HandoffRecord;
};

export class MemoryArtifactStore implements ArtifactStore {
  private readonly entries = new Map<string, MemoryEntry>();

  async initialize(): Promise<void> {}
  async close(): Promise<void> {}
  async ping(): Promise<void> {}

  async registerState(id: string, expiresAt: number): Promise<boolean> {
    return this.register("state", id, expiresAt);
  }

  async consumeState(id: string): Promise<boolean> {
    return this.consume("state", id) !== undefined;
  }

  async registerRequest(
    clientId: string,
    requestId: string,
    expiresAt: number,
  ): Promise<boolean> {
    return this.register("request", `${clientId}:${requestId}`, expiresAt);
  }

  async putHandoff(code: string, record: HandoffRecord): Promise<void> {
    this.prune();
    const key = digest("handoff", code);
    if (this.entries.has(key)) throw new Error("handoff collision");
    this.entries.set(key, { kind: "handoff", expiresAt: record.expiresAt, handoff: record });
  }

  async consumeHandoff(
    code: string,
    expected: Pick<HandoffRecord, "clientId" | "siteId" | "provider" | "nonce">,
  ): Promise<HandoffRecord | undefined> {
    this.prune();
    const key = digest("handoff", code);
    const entry = this.entries.get(key);
    const handoff = entry?.kind === "handoff" ? entry.handoff : undefined;
    if (
      !handoff ||
      handoff.clientId !== expected.clientId ||
      handoff.siteId !== expected.siteId ||
      handoff.provider !== expected.provider ||
      handoff.nonce !== expected.nonce
    ) {
      return undefined;
    }
    this.entries.delete(key);
    return handoff;
  }

  private register(kind: "state" | "request", id: string, expiresAt: number): boolean {
    this.prune();
    const key = digest(kind, id);
    if (this.entries.has(key)) return false;
    this.entries.set(key, { kind, expiresAt });
    return true;
  }

  private consume(kind: "state" | "request", id: string): MemoryEntry | undefined {
    this.prune();
    const key = digest(kind, id);
    const entry = this.entries.get(key);
    if (!entry || entry.kind !== kind) return undefined;
    this.entries.delete(key);
    return entry;
  }

  private prune(): void {
    const now = Math.floor(Date.now() / 1000);
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
  }
}

export class PostgresArtifactStore implements ArtifactStore {
  private readonly pool: Pool;

  constructor(databaseUrl: string) {
    this.pool = new Pool({
      connectionString: databaseUrl,
      max: 10,
      connectionTimeoutMillis: 5_000,
      idleTimeoutMillis: 30_000,
    });
  }

  async initialize(): Promise<void> {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS admitone_connect_artifacts (
        digest TEXT PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('state', 'request', 'handoff')),
        client_id TEXT,
        site_id TEXT,
        provider TEXT,
        nonce_digest TEXT,
        sealed_payload TEXT,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await this.pool.query(`
      CREATE INDEX IF NOT EXISTS admitone_connect_artifacts_expiry_idx
      ON admitone_connect_artifacts (expires_at)
    `);
    await this.prune();
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  async ping(): Promise<void> {
    await this.pool.query("SELECT 1");
  }

  async registerState(id: string, expiresAt: number): Promise<boolean> {
    return this.register("state", id, expiresAt);
  }

  async consumeState(id: string): Promise<boolean> {
    const result = await this.pool.query(
      `DELETE FROM admitone_connect_artifacts
       WHERE digest = $1 AND kind = 'state' AND expires_at > NOW()
       RETURNING digest`,
      [digest("state", id)],
    );
    return result.rowCount === 1;
  }

  async registerRequest(
    clientId: string,
    requestId: string,
    expiresAt: number,
  ): Promise<boolean> {
    return this.register("request", `${clientId}:${requestId}`, expiresAt, clientId);
  }

  async putHandoff(code: string, record: HandoffRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO admitone_connect_artifacts
        (digest, kind, client_id, site_id, provider, nonce_digest, sealed_payload, expires_at)
       VALUES ($1, 'handoff', $2, $3, $4, $5, $6, TO_TIMESTAMP($7))`,
      [
        digest("handoff", code),
        record.clientId,
        record.siteId,
        record.provider,
        digest("nonce", record.nonce),
        record.sealedPayload,
        record.expiresAt,
      ],
    );
  }

  async consumeHandoff(
    code: string,
    expected: Pick<HandoffRecord, "clientId" | "siteId" | "provider" | "nonce">,
  ): Promise<HandoffRecord | undefined> {
    const result = await this.pool.query<{
      client_id: string;
      site_id: string;
      provider: Provider;
      sealed_payload: string;
      expires_at_epoch: string;
    }>(
      `DELETE FROM admitone_connect_artifacts
       WHERE digest = $1
         AND kind = 'handoff'
         AND client_id = $2
         AND site_id = $3
         AND provider = $4
         AND nonce_digest = $5
         AND expires_at > NOW()
       RETURNING client_id, site_id, provider, sealed_payload,
                 EXTRACT(EPOCH FROM expires_at)::BIGINT AS expires_at_epoch`,
      [
        digest("handoff", code),
        expected.clientId,
        expected.siteId,
        expected.provider,
        digest("nonce", expected.nonce),
      ],
    );
    const row = result.rows[0];
    if (!row) return undefined;
    return {
      clientId: row.client_id,
      siteId: row.site_id,
      provider: row.provider,
      nonce: expected.nonce,
      sealedPayload: row.sealed_payload,
      expiresAt: Number(row.expires_at_epoch),
    };
  }

  private async register(
    kind: "state" | "request",
    id: string,
    expiresAt: number,
    clientId?: string,
  ): Promise<boolean> {
    const result = await this.pool.query(
      `INSERT INTO admitone_connect_artifacts (digest, kind, client_id, expires_at)
       VALUES ($1, $2, $3, TO_TIMESTAMP($4))
       ON CONFLICT (digest) DO NOTHING`,
      [digest(kind, id), kind, clientId ?? null, expiresAt],
    );
    return result.rowCount === 1;
  }

  private async prune(): Promise<void> {
    await this.pool.query("DELETE FROM admitone_connect_artifacts WHERE expires_at <= NOW()");
  }
}

function digest(namespace: string, value: string): string {
  return crypto.createHash("sha256").update(`${namespace}\0${value}`, "utf8").digest("hex");
}
