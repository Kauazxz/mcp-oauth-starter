/**
 * Persistence for the authorization server, behind an interface so a SQL adapter can
 * replace the in-memory one without touching the OAuth logic.
 *
 * Every credential (authorization code, access token, refresh token) is keyed by its
 * SHA-256 hash; the plaintext never reaches the store.
 */

export interface Client {
  clientId: string;
  clientName?: string;
  redirectUris: string[];
  scope?: string;
  createdAt: number;
}

/** A validated /authorize request waiting for the user to log in and consent. */
export interface PendingAuthorization {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource: string;
  state?: string;
  failedLogins: number;
  expiresAt: number;
}

interface Grant {
  clientId: string;
  userId: string;
  scopes: string[];
  resource: string;
  /** Every token descending from one authorization code shares a family. */
  familyId: string;
  expiresAt: number;
}

export interface AuthorizationCode extends Grant {
  redirectUri: string;
  codeChallenge: string;
  usedAt?: number;
}

export type AccessToken = Grant;

export interface RefreshToken extends Grant {
  usedAt?: number;
}

export interface OAuthStore {
  saveClient(client: Client): Promise<void>;
  getClient(clientId: string): Promise<Client | undefined>;

  savePending(id: string, pending: PendingAuthorization): Promise<void>;
  getPending(id: string): Promise<PendingAuthorization | undefined>;
  deletePending(id: string): Promise<void>;

  saveCode(hash: string, code: AuthorizationCode): Promise<void>;
  getCode(hash: string): Promise<AuthorizationCode | undefined>;

  saveAccessToken(hash: string, token: AccessToken): Promise<void>;
  getAccessToken(hash: string): Promise<AccessToken | undefined>;

  saveRefreshToken(hash: string, token: RefreshToken): Promise<void>;
  getRefreshToken(hash: string): Promise<RefreshToken | undefined>;

  /**
   * Atomically flags a code or refresh token as used. Returns false when it was already
   * used, which is how replays are detected. A SQL adapter should implement this as
   * `UPDATE ... SET used_at = now() WHERE hash = $1 AND used_at IS NULL` and check the row count.
   */
  markUsed(kind: "code" | "refresh", hash: string, now: number): Promise<boolean>;

  /** Invalidates every access and refresh token of a family (reuse detection). */
  revokeFamily(familyId: string, until: number): Promise<void>;
  isFamilyRevoked(familyId: string): Promise<boolean>;
}

/** Single-process store. Data is lost on restart and not shared between replicas. */
export class MemoryStore implements OAuthStore {
  private clients = new Map<string, Client>();
  private pending = new Map<string, PendingAuthorization>();
  private codes = new Map<string, AuthorizationCode>();
  private accessTokens = new Map<string, AccessToken>();
  private refreshTokens = new Map<string, RefreshToken>();
  /** familyId -> moment after which every token of the family has expired anyway. */
  private revokedFamilies = new Map<string, number>();
  private lastSweep = 0;

  constructor(private readonly now: () => number = Date.now) {}

  async saveClient(client: Client) {
    this.clients.set(client.clientId, client);
  }
  async getClient(clientId: string) {
    return this.clients.get(clientId);
  }

  async savePending(id: string, pending: PendingAuthorization) {
    this.sweep();
    this.pending.set(id, pending);
  }
  async getPending(id: string) {
    return this.live(this.pending.get(id));
  }
  async deletePending(id: string) {
    this.pending.delete(id);
  }

  async saveCode(hash: string, code: AuthorizationCode) {
    this.sweep();
    this.codes.set(hash, code);
  }
  async getCode(hash: string) {
    // Expired codes are returned too: the caller needs `usedAt`/`familyId` for replay handling.
    return this.codes.get(hash);
  }

  async saveAccessToken(hash: string, token: AccessToken) {
    this.sweep();
    this.accessTokens.set(hash, token);
  }
  async getAccessToken(hash: string) {
    return this.live(this.accessTokens.get(hash));
  }

  async saveRefreshToken(hash: string, token: RefreshToken) {
    this.refreshTokens.set(hash, token);
  }
  async getRefreshToken(hash: string) {
    return this.refreshTokens.get(hash);
  }

  async markUsed(kind: "code" | "refresh", hash: string, now: number) {
    const record = kind === "code" ? this.codes.get(hash) : this.refreshTokens.get(hash);
    if (!record || record.usedAt !== undefined) return false;
    record.usedAt = now;
    return true;
  }

  async revokeFamily(familyId: string, until: number) {
    this.revokedFamilies.set(familyId, Math.max(until, this.revokedFamilies.get(familyId) ?? 0));
  }
  async isFamilyRevoked(familyId: string) {
    return this.revokedFamilies.has(familyId);
  }

  private live<T extends { expiresAt: number }>(record: T | undefined): T | undefined {
    return record && record.expiresAt > this.now() ? record : undefined;
  }

  /** Drops expired entries at most once a minute so memory does not grow forever. */
  private sweep() {
    const now = this.now();
    if (now - this.lastSweep < 60_000) return;
    this.lastSweep = now;
    for (const map of [this.pending, this.codes, this.accessTokens, this.refreshTokens]) {
      for (const [key, value] of map) if (value.expiresAt <= now) map.delete(key);
    }
    for (const [key, until] of this.revokedFamilies) if (until <= now) this.revokedFamilies.delete(key);
  }
}
