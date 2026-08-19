import assert from "node:assert/strict";
import test from "node:test";
import {
  classifyInitialDoormanRequest,
  createDoorman,
  normalizeDoormanPath,
  recommendationForRisk,
  riskBand,
  routeShape,
} from "../src/index.mjs";

test("known crawler identity stays separate from risk", () => {
  const result = classifyInitialDoormanRequest({
    userAgent: "Mozilla/5.0 AppleWebKit/537.36; compatible; GPTBot/1.3",
    path: "/records",
    browserNavigation: false,
  });
  assert.equal(result.classification, "known_crawler");
  assert.equal(result.automationConfidence, 100);
  assert.equal(result.riskScore, 4);
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
