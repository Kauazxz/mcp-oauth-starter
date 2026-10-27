import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { loadConfig } from "../src/config.js";
import { safeEqual, verifyPkce } from "../src/crypto.js";

describe("config", () => {
  const base = { DEMO_USERNAME: "demo", DEMO_PASSWORD: "long-enough-password" };

  it("derives the resource from the issuer and applies defaults", () => {
    const config = loadConfig({ ...base, ISSUER_URL: "https://mcp.example.com" });
    assert.equal(config.issuer, "https://mcp.example.com");
    assert.equal(config.resource, "https://mcp.example.com/mcp");
    assert.equal(config.accessTokenTtlSeconds, 600);
    assert.equal(config.trustProxy, false);
  });

  it("refuses plain http outside loopback, issuers with a path, and missing secrets", () => {
    assert.throws(() => loadConfig({ ...base, ISSUER_URL: "http://mcp.example.com" }), /https/);
    assert.throws(() => loadConfig({ ...base, ISSUER_URL: "https://mcp.example.com/base" }), /origin/);
    assert.throws(() => loadConfig({ DEMO_USERNAME: "demo" }), /DEMO_PASSWORD/);
    assert.throws(() => loadConfig({ ...base, DEMO_PASSWORD: "short" }), /at least 8/);
  });
});

describe("crypto helpers", () => {
  it("compares strings of different lengths without throwing", () => {
    assert.equal(safeEqual("a", "a"), true);
    assert.equal(safeEqual("a", "ab"), false);
  });

  it("verifies the RFC 7636 appendix B example", () => {
    assert.equal(
      verifyPkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
      true,
    );
    assert.equal(verifyPkce("too-short", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"), false);
  });
});
