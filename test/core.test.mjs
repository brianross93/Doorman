import assert from "node:assert/strict";
import test from "node:test";
import { signatureHeaders } from "web-bot-auth";
import { signerFromJWK } from "web-bot-auth/crypto";
import {
  classifyInitialDoormanRequest,
  createCloudflareIdentityProvider,
  createDoorman,
  createRegistryIdentityProvider,
  createWebBotAuthIdentityProvider,
  normalizeDoormanPath,
  recommendationForRisk,
  riskBand,
  routeShape,
  trafficRoleHypothesis,
} from "../src/index.mjs";

const TEST_PRIVATE_JWK = {
  kty: "OKP",
  crv: "Ed25519",
  kid: "test-key-ed25519",
  d: "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

const TEST_PUBLIC_JWK = {
  kty: "OKP",
  crv: "Ed25519",
  kid: "test-key-ed25519",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

test("known crawler identity stays separate from risk", () => {
  const result = classifyInitialDoormanRequest({
    userAgent: "Mozilla/5.0 AppleWebKit/537.36; compatible; GPTBot/1.3",
    path: "/records",
    browserNavigation: false,
  });
  assert.equal(result.classification, "known_crawler");
  assert.equal(result.automationConfidence, 100);
  assert.equal(result.riskScore, 4);
  assert.equal(result.identity.assurance, "self_declared");
  assert.equal(result.identity.verified, false);
});

test("a claimed crawler identity does not suppress behavioral risk", () => {
  const result = classifyInitialDoormanRequest({
    userAgent: "Googlebot/2.1",
    path: "/wp-admin/install.php",
  });
  assert.equal(result.classification, "known_crawler");
  assert.equal(result.identity.assurance, "self_declared");
  assert.equal(riskBand(result.riskScore), "high");
  assert.match(result.evidence.join(" "), /exploit-probe/i);
});

test("automation clients are identified without calling them malicious", () => {
  const result = classifyInitialDoormanRequest({
    userAgent: "curl/8.12.1",
    path: "/claims",
    browserNavigation: false,
  });
  assert.equal(result.classification, "likely_automation");
  assert.ok(result.automationConfidence >= 90);
  assert.ok(result.riskScore < 20);
});

test("a crawler trap indicates automation without calling the visitor malicious", () => {
  const result = classifyInitialDoormanRequest({
    userAgent:
      "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 Version/13.0.3 Mobile/15E148 Safari/604.1",
    path: "/doorman-trap/7d92",
    browserNavigation: true,
  });
  assert.equal(result.classification, "likely_automation");
  assert.ok(result.automationConfidence >= 90);
  assert.equal(riskBand(result.riskScore), "low");
  assert.match(recommendationForRisk(result.riskScore), /allow/i);
  assert.match(result.evidence.join(" "), /not malicious by itself/i);
});

test("sparse browser-like trap traffic is presented as a likely browser agent", () => {
  const hypothesis = trafficRoleHypothesis({
    classification: "likely_automation",
    classificationConfidence: 92,
    riskScore: 28,
    requestCount: 1,
    errorCount: 0,
    trapHits: 1,
    userAgentExcerpt:
      "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 Version/13.0.3 Mobile/15E148 Safari/604.1",
    evidence: [
      "Hidden crawler trap requested",
      "Trap access indicates automation but is not malicious by itself",
    ],
  });
  assert.equal(hypothesis.key, "likely_browser_agent");
  assert.equal(hypothesis.label, "Likely Browser Agent");
  assert.equal(hypothesis.verified, false);
  assert.ok(hypothesis.confidence <= 70);
  assert.match(hypothesis.explanation, /could also be a crawler/i);
});

test("abusive browser automation remains likely automation", () => {
  const hypothesis = trafficRoleHypothesis({
    classification: "likely_automation",
    classificationConfidence: 97,
    riskScore: 86,
    requestCount: 94,
    errorCount: 12,
    trapHits: 1,
    userAgentExcerpt: "Mozilla/5.0 HeadlessChrome/136.0.0.0 Safari/537.36",
    evidence: ["Crawler trap access combined with abusive request behavior"],
  });
  assert.equal(hypothesis.key, "likely_automation");
  assert.equal(hypothesis.label, "Likely Automation");
});

test("ordinary browser navigation stays unknown until a beacon arrives", () => {
  const result = classifyInitialDoormanRequest({
    userAgent: "Mozilla/5.0 Chrome/136.0.0.0 Safari/537.36",
    path: "/records",
    browserNavigation: true,
  });
  assert.equal(result.classification, "unknown");
  assert.ok(result.automationConfidence < 30);
  assert.match(result.evidence.join(" "), /browser navigation/i);
});

test("a presented signature is not mislabeled as verified", () => {
  const result = classifyInitialDoormanRequest({
    userAgent: "research-agent/0.1",
    path: "/mcp",
    browserNavigation: false,
    signaturePresented: true,
  });
  assert.notEqual(result.classification, "verified_agent");
  assert.match(result.evidence.join(" "), /not yet verified/i);
});

test("common exploit probes are high risk", () => {
  const result = classifyInitialDoormanRequest({
    userAgent: "Mozilla/5.0",
    path: "/wp-admin/install.php",
    browserNavigation: false,
  });
  assert.equal(result.classification, "likely_automation");
  assert.equal(result.userAgentLabel, "Unidentified exploit scanner");
  assert.equal(riskBand(result.riskScore), "high");
  assert.match(recommendationForRisk(result.riskScore), /block/i);
});

test("route shaping groups resources without retaining query strings", () => {
  assert.equal(
    routeShape("/records/9df551f7-211a-430c-95ea-05796220760e?secret=no"),
    "/records/:id",
  );
  assert.equal(routeShape("/profiles/12345"), "/profiles/:id");
  assert.equal(normalizeDoormanPath("claims?page=2"), "/claims");
});

test("sites can add their own identity rules", () => {
  const doorman = createDoorman({
    knownCrawlers: [["Community archive", /CommunityArchiveBot/i]],
  });
  const result = doorman.inspect({
    userAgent: "CommunityArchiveBot/1.0",
    path: "/public",
  });
  assert.equal(result.classification, "known_crawler");
  assert.equal(result.userAgentLabel, "Community archive");
});

test("a registry match is listed identity evidence, not verified identity", async () => {
  const doorman = createDoorman({
    identityProviders: [
      createRegistryIdentityProvider([
        {
          name: "Community Research Crawler",
          operator: "Community Lab",
          purpose: "research",
          kind: "BOT",
          userAgentPatterns: ["CommunityResearchBot/*"],
        },
      ]),
    ],
  });
  const result = await doorman.inspectRequest(new Request("https://example.com/public", {
    headers: { "user-agent": "CommunityResearchBot/1.0" },
  }));
  assert.equal(result.classification, "known_crawler");
  assert.equal(result.identity.assurance, "directory_listed");
  assert.equal(result.identity.verified, false);
  assert.equal(result.identity.operator, "Community Lab");
});

test("Cloudflare metadata is ignored unless the host marks it trusted", async () => {
  const request = new Request("https://example.com", {
    headers: { "user-agent": "Research-Agent/1.0" },
  });
  Object.defineProperty(request, "cf", {
    value: { botManagement: { signedAgent: true, score: 1 } },
  });
  const doorman = createDoorman({
    identityProviders: [createCloudflareIdentityProvider()],
  });
  const result = await doorman.inspectRequest(request);
  assert.equal(result.classification, "unknown");
  assert.equal(result.identity, null);
});

test("trusted Cloudflare signed-agent metadata produces provider-attested identity", async () => {
  const doorman = createDoorman({
    identityProviders: [createCloudflareIdentityProvider({ trusted: true })],
  });
  const result = await doorman.inspectRequest(
    new Request("https://example.com", { headers: { "user-agent": "Research-Agent/1.0" } }),
    {
      cloudflare: {
        botManagement: { signedAgent: true, score: 1 },
        verifiedBotCategory: "AI Assistant",
      },
      cloudflareIdentity: {
        name: "Research Agent",
        operator: "Community Lab",
      },
    },
  );
  assert.equal(result.classification, "verified_agent");
  assert.equal(result.identity.assurance, "provider_attested");
  assert.equal(result.identity.verified, true);
  assert.equal(result.riskScore, 5);
});

test("Cloudflare bot score can raise automation confidence without raising risk", async () => {
  const doorman = createDoorman({
    identityProviders: [createCloudflareIdentityProvider({ trusted: true })],
  });
  const result = await doorman.inspectRequest(
    new Request("https://example.com", { headers: { "user-agent": "Mozilla/5.0" } }),
    { cloudflare: { botManagement: { score: 2 } } },
  );
  assert.equal(result.classification, "likely_automation");
  assert.ok(result.automationConfidence >= 98);
  assert.equal(result.riskScore, 5);
});

test("an unavailable identity provider does not break request inspection", async () => {
  const doorman = createDoorman({
    identityProviders: [async () => {
      throw new Error("directory offline");
    }],
  });
  const result = await doorman.inspectRequest(new Request("https://example.com"));
  assert.equal(result.classification, "unknown");
  assert.match(result.evidence.join(" "), /continued without it/i);
});

async function signedRequest(url = "https://example.com/resource") {
  const signatureAgent = "https://agent.example/.well-known/http-message-signature-directory";
  const unsigned = new Request(url, {
    headers: {
      "signature-agent": `"${signatureAgent}"`,
      "user-agent": "Research-Agent/1.0",
    },
  });
  const now = new Date();
  const signed = await signatureHeaders(
    unsigned,
    await signerFromJWK(TEST_PRIVATE_JWK),
    { created: now, expires: new Date(now.getTime() + 300_000) },
  );
  return new Request(url, {
    headers: {
      "signature-agent": `"${signatureAgent}"`,
      "user-agent": "Research-Agent/1.0",
      Signature: signed.Signature,
      "Signature-Input": signed["Signature-Input"],
    },
  });
}

test("Web Bot Auth verifies a signed request with a trusted public key", async () => {
  const doorman = createDoorman({
    identityProviders: [
      createWebBotAuthIdentityProvider({
        resolveKey: async ({ keyid, signatureAgent }) => {
          assert.ok(keyid);
          assert.equal(
            signatureAgent,
            "https://agent.example/.well-known/http-message-signature-directory",
          );
          return {
            jwk: TEST_PUBLIC_JWK,
            identity: {
              type: "agent",
              name: "Test Research Agent",
              operator: "Community Lab",
              purpose: "research",
            },
          };
        },
      }),
    ],
  });
  const result = await doorman.inspectRequest(await signedRequest());
  assert.equal(result.classification, "verified_agent");
  assert.equal(result.identity.assurance, "cryptographic");
  assert.equal(result.identity.name, "Test Research Agent");
  assert.equal(result.identity.verified, true);
  assert.match(result.evidence.join(" "), /signature verified/i);
});

test("a failed signature for a trusted key adds risk and never verifies identity", async () => {
  const valid = await signedRequest();
  const tampered = new Request("https://different.example/resource", {
    headers: valid.headers,
  });
  const doorman = createDoorman({
    identityProviders: [
      createWebBotAuthIdentityProvider({
        resolveKey: async () => ({ jwk: TEST_PUBLIC_JWK }),
      }),
    ],
  });
  const result = await doorman.inspectRequest(tampered);
  assert.notEqual(result.classification, "verified_agent");
  assert.equal(result.identity, null);
  assert.equal(result.riskScore, 25);
  assert.match(result.evidence.join(" "), /verification failed/i);
});

test("a signed request with no trusted key remains unverified without a penalty", async () => {
  const doorman = createDoorman({
    identityProviders: [
      createWebBotAuthIdentityProvider({ resolveKey: async () => null }),
    ],
  });
  const result = await doorman.inspectRequest(await signedRequest());
  assert.notEqual(result.classification, "verified_agent");
  assert.equal(result.identity, null);
  assert.equal(result.riskScore, 5);
  assert.match(result.evidence.join(" "), /no trusted key/i);
});
