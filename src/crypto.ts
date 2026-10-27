import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** 256 bits of randomness, URL-safe. `prefix` makes leaked tokens easy to grep and to secret-scan. */
export function randomToken(prefix = ""): string {
  return prefix + randomBytes(32).toString("base64url");
}

/** Tokens and codes are stored only as SHA-256 digests: a leaked store does not leak credentials. */
export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

/**
 * Constant-time string comparison. Hashing first gives both sides the same length,
 * so neither the content nor the length of the secret leaks through timing.
 */
export function safeEqual(a: string, b: string): boolean {
  return timingSafeEqual(createHash("sha256").update(a).digest(), createHash("sha256").update(b).digest());
}

/** RFC 7636 §4.1: 43–128 characters from the unreserved set. */
const PKCE_VALUE = /^[A-Za-z0-9\-._~]{43,128}$/;

export function isValidPkceValue(value: string): boolean {
  return PKCE_VALUE.test(value);
}

/** RFC 7636 §4.6 with the S256 method (the only one this server accepts). */
export function verifyPkce(codeVerifier: string, codeChallenge: string): boolean {
  if (!isValidPkceValue(codeVerifier)) return false;
  return safeEqual(sha256(codeVerifier), codeChallenge);
}
