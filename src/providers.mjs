import { verify as verifyWebBotAuth } from "web-bot-auth";
import { verifierFromJWK } from "web-bot-auth/crypto";

const CLOUDFLARE_RADAR_BOTS_URL =
  "https://api.cloudflare.com/client/v4/radar/bots";

const ASSURANCE_RANK = Object.freeze({
  none: 0,
  self_declared: 1,
  directory_listed: 2,
  provider_attested: 3,
  cryptographic: 4,
});

function clamp(value, minimum = 0, maximum = 100) {
  return Math.min(maximum, Math.max(minimum, Number(value) || 0));
}

function headerValue(headers, name) {
  if (!headers) return null;
  if (typeof headers.get === "function") return headers.get(name);
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) return String(value);
  }
  return null;
}

function normalizedSignatureAgent(value) {
  const raw = String(value || "").trim();
  if (!raw) return null;
  const unquoted = raw.startsWith('"') && raw.endsWith('"')
    ? raw.slice(1, -1)
    : raw;
  try {
    const url = new URL(unquoted);
    return url.protocol === "https:" ? url.toString() : null;
  } catch {
    return null;
  }
}

function normalizedPurpose(value) {
  return String(value || "other")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "") || "other";
}

function typeForDirectoryEntry(entry) {
  const purpose = normalizedPurpose(entry.purpose || entry.category);
  if (
    String(entry.kind || "").toUpperCase() === "AGENT" ||
    ["agent", "ai_assistant", "transact"].includes(purpose)
  ) {
    return "agent";
  }
  return "bot";
}

function wildcardPattern(value) {
  const raw = String(value || "").slice(0, 240);
  const escaped = raw.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
  return new RegExp(escaped.replace(/\*/g, ".*"), "i");
}

export function normalizeIdentityEvidence(identity = {}) {
  const assurance = Object.hasOwn(ASSURANCE_RANK, identity.assurance)
    ? identity.assurance
    : "none";
  const type = ["human", "agent", "bot", "unknown"].includes(identity.type)
    ? identity.type
    : "unknown";
  return Object.freeze({
    type,
    name: String(identity.name || (type === "unknown" ? "Unknown" : type)),
    operator: identity.operator ? String(identity.operator) : null,
    purpose: normalizedPurpose(identity.purpose),
    accessMode: identity.accessMode ? String(identity.accessMode) : null,
    assurance,
    source: String(identity.source || "unknown"),
    verified: assurance === "provider_attested" || assurance === "cryptographic",
    signatureAgent: normalizedSignatureAgent(identity.signatureAgent),
  });
}

export function strongerIdentity(left, right) {
  if (!left) return right ? normalizeIdentityEvidence(right) : null;
  if (!right) return normalizeIdentityEvidence(left);
  const normalizedLeft = normalizeIdentityEvidence(left);
  const normalizedRight = normalizeIdentityEvidence(right);
  return ASSURANCE_RANK[normalizedRight.assurance] > ASSURANCE_RANK[normalizedLeft.assurance]
    ? normalizedRight
    : normalizedLeft;
}

export function createRegistryIdentityProvider(entries = [], options = {}) {
  const source = String(options.source || "identity_registry");
  const compiled = entries.flatMap((entry) => {
    const patterns = entry.userAgentPatterns || entry.userAgents || [];
    return patterns.map((pattern) => ({
      entry,
      pattern: pattern instanceof RegExp ? pattern : wildcardPattern(pattern),
    }));
  });

  return async ({ input }) => {
    const userAgent = String(input.userAgent || "");
    const match = compiled.find(({ pattern }) => pattern.test(userAgent));
    if (!match) return null;
    const entry = match.entry;
    return {
      identity: normalizeIdentityEvidence({
        type: typeForDirectoryEntry(entry),
        name: entry.name,
        operator: entry.operator,
        purpose: entry.purpose || entry.category,
        accessMode: entry.accessMode,
        assurance: "directory_listed",
        source,
        signatureAgent: entry.signatureAgentUrl,
      }),
      classificationConfidence: 84,
      automationConfidence: 99,
      evidence: [
        `${entry.name || "Automated client"} matched the ${source} directory`,
        "Directory and user-agent matches identify a claim, not the individual request cryptographically",
      ],
    };
  };
}

export async function fetchCloudflareRadarDirectory(options = {}) {
  const apiToken = String(options.apiToken || "").trim();
  if (!apiToken) throw new Error("A Cloudflare API token is required");
  const fetchImpl = options.fetch || globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new Error("A fetch implementation is required");
  const limit = Math.min(5000, Math.max(1, Number(options.limit || 1000)));
  const url = new URL(options.endpoint || CLOUDFLARE_RADAR_BOTS_URL);
  url.searchParams.set("limit", String(limit));
  url.searchParams.set("botVerificationStatus", "VERIFIED");
  const response = await fetchImpl(url, {
    headers: { authorization: `Bearer ${apiToken}` },
    signal: options.signal,
  });
  if (!response.ok) {
    throw new Error(`Cloudflare Radar returned HTTP ${response.status}`);
  }
  const payload = await response.json();
  const bots = payload?.result?.bots;
  if (!Array.isArray(bots)) throw new Error("Cloudflare Radar returned an invalid bot directory");
  return bots.map((bot) => ({
    name: bot.name,
    operator: bot.operator,
    category: bot.category,
    kind: bot.kind,
    slug: bot.slug,
    userAgentPatterns: Array.isArray(bot.userAgentPatterns)
      ? bot.userAgentPatterns
      : [],
    source: "cloudflare_radar",
  }));
}

export function createCloudflareIdentityProvider(options = {}) {
  const trusted = options.trusted === true;
  return async ({ request, context = {} }) => {
    if (!trusted) return null;
    const cf = options.getMetadata
      ? await options.getMetadata(request, context)
      : context.cloudflare || request?.cf;
    const bot = cf?.botManagement;
    if (!bot) return null;

    const score = Number(bot.score);
    const category = cf.verifiedBotCategory || bot.category || "other";
    const signedAgent = bot.signedAgent === true;
    const verifiedBot = bot.verifiedBot === true;
    const evidence = [];
    if (Number.isFinite(score)) evidence.push(`Cloudflare bot score: ${score}`);

    if (signedAgent || verifiedBot) {
      const type = signedAgent ? "agent" : "bot";
      evidence.push(signedAgent
        ? "Cloudflare attested a signed agent"
        : "Cloudflare attested a verified bot");
      return {
        identity: normalizeIdentityEvidence({
          type,
          name: context.cloudflareIdentity?.name || (signedAgent ? "Signed agent" : "Verified bot"),
          operator: context.cloudflareIdentity?.operator,
          purpose: category,
          accessMode: context.cloudflareIdentity?.accessMode,
          assurance: "provider_attested",
          source: "cloudflare",
        }),
        classificationConfidence: 99,
        automationConfidence: 100,
        evidence,
      };
    }

    if (!Number.isFinite(score)) return null;
    const automationConfidence = clamp(100 - score);
    if (score >= 80 && bot.jsDetection?.passed === true) {
      evidence.push("Cloudflare JavaScript detection passed");
      return {
        classification: "human",
        classificationConfidence: score,
        automationConfidence,
        evidence,
      };
    }
    if (score <= 29) {
      return {
        classification: "likely_automation",
        classificationConfidence: clamp(100 - score),
        automationConfidence,
        evidence,
      };
    }
    return { automationConfidence, evidence };
  };
}

class UnknownWebBotAuthKeyError extends Error {}

export function createWebBotAuthIdentityProvider(options = {}) {
  if (typeof options.resolveKey !== "function") {
    throw new TypeError("createWebBotAuthIdentityProvider requires resolveKey");
  }

  return async ({ request }) => {
    const headers = request?.headers;
    const signature = headerValue(headers, "signature");
    const signatureInput = headerValue(headers, "signature-input");
    if (!signature || !signatureInput) return null;

    const signatureAgent = normalizedSignatureAgent(
      headerValue(headers, "signature-agent"),
    );
    let resolved = null;
    try {
      await verifyWebBotAuth(request, async (data, signatureBytes, params) => {
        resolved = await options.resolveKey({
          keyid: params.keyid,
          signatureAgent,
          request,
        });
        if (!resolved?.jwk) throw new UnknownWebBotAuthKeyError();
        if (resolved.jwk.d) throw new Error("Private JWK material is not accepted");
        const verifyWithKey = await verifierFromJWK(resolved.jwk);
        await verifyWithKey(data, signatureBytes, params);
      });

      const suppliedIdentity = resolved.identity || {};
      return {
        identity: normalizeIdentityEvidence({
          type: suppliedIdentity.type || "agent",
          name: suppliedIdentity.name || signatureAgent || "Verified agent",
          operator: suppliedIdentity.operator,
          purpose: suppliedIdentity.purpose || "agent",
          accessMode: suppliedIdentity.accessMode,
          assurance: "cryptographic",
          source: "web_bot_auth",
          signatureAgent,
        }),
        classificationConfidence: 100,
        automationConfidence: 100,
        evidence: ["Web Bot Auth HTTP message signature verified"],
      };
    } catch (error) {
      if (error instanceof UnknownWebBotAuthKeyError || !resolved?.jwk) {
        return {
          evidence: ["Web Bot Auth signature was present but no trusted key was available"],
        };
      }
      return {
        riskDelta: 20,
        evidence: ["Web Bot Auth verification failed for a trusted key"],
      };
    }
  };
}
