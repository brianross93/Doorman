import {
  createCloudflareIdentityProvider,
  createRegistryIdentityProvider,
  createWebBotAuthIdentityProvider,
  fetchCloudflareRadarDirectory,
  normalizeIdentityEvidence,
  strongerIdentity,
} from "./providers.mjs";

const DEFAULT_KNOWN_CRAWLERS = [
  ["OpenAI Search", /\bOAI-SearchBot\b/i, "search"],
  ["ChatGPT User", /\bChatGPT-User\b/i, "user_action"],
  ["OpenAI GPTBot", /\bGPTBot\b/i, "ai_crawler"],
  ["Anthropic ClaudeBot", /\bClaudeBot\b/i, "ai_crawler"],
  ["Anthropic Claude Search", /\bClaude-SearchBot\b/i, "search"],
  ["PerplexityBot", /\bPerplexityBot\b/i, "ai_crawler"],
  ["Googlebot", /\bGooglebot\b/i, "search"],
  ["Bingbot", /\bbingbot\b/i, "search"],
  ["Applebot", /\bApplebot\b/i, "search"],
  ["Amazonbot", /\bAmazonbot\b/i, "ai_crawler"],
  ["Meta crawler", /\b(?:Meta-ExternalAgent|FacebookBot)\b/i, "ai_crawler"],
  ["Bytespider", /\bBytespider\b/i, "ai_crawler"],
  ["Common Crawl", /\bCCBot\b/i, "archive"],
];

const DEFAULT_AUTOMATION_CLIENTS = [
  ["curl", /\bcurl\//i],
  ["wget", /\bWget\//i],
  ["Python client", /\b(?:python-requests|aiohttp|httpx)\b/i],
  ["Go HTTP client", /\bGo-http-client\b/i],
  ["Node client", /\b(?:node-fetch|undici|axios)\b/i],
  ["Playwright", /\bPlaywright\b/i],
  ["Puppeteer", /\bPuppeteer\b/i],
  ["Headless Chrome", /\bHeadlessChrome\b/i],
];

const EXPLOIT_PROBE = /\/(?:wp-admin|wp-login|phpmyadmin|\.env)(?:\/|$)|\/xmlrpc\.php$/i;
const CRAWLER_TRAP = /^\/doorman-trap(?:\/|$)/i;

export const DOORMAN_CLASSIFICATIONS = Object.freeze([
  "human",
  "verified_agent",
  "verified_bot",
  "known_crawler",
  "likely_automation",
  "unknown",
]);

function clamp(value, minimum = 0, maximum = 100) {
  return Math.min(maximum, Math.max(minimum, Number(value) || 0));
}

export function normalizeDoormanPath(value) {
  const path = String(value || "/").split(/[?#]/, 1)[0] || "/";
  return (path.startsWith("/") ? path : `/${path}`).slice(0, 240);
}

export function routeShape(value) {
  return normalizeDoormanPath(value)
    .replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, ":id")
    .replace(/\/\d{2,}(?=\/|$)/g, "/:id");
}

function initialInspection(input, knownCrawlers, automationClients) {
  const userAgent = String(input.userAgent || "").slice(0, 320);
  const path = normalizeDoormanPath(input.path);
  const evidence = [];
  let classification = "unknown";
  let classificationConfidence = input.browserNavigation ? 58 : 45;
  let automationConfidence = input.browserNavigation ? 24 : 56;
  let riskScore = 5;
  let userAgentLabel = browserLabel(userAgent);
  let identity = null;

  const crawler = knownCrawlers.find(([, pattern]) => pattern.test(userAgent));
  if (crawler) {
    const [label, , purpose = "crawler"] = crawler;
    classification = "known_crawler";
    classificationConfidence = 72;
    automationConfidence = 100;
    riskScore = 4;
    userAgentLabel = label;
    identity = normalizeIdentityEvidence({
      type: "bot",
      name: label,
      purpose,
      assurance: "self_declared",
      source: "user_agent",
    });
    evidence.push(
      `Known crawler user agent claimed: ${label}`,
      "User agent is evidence, not cryptographic proof",
    );
  } else {
    const automation = automationClients.find(([, pattern]) => pattern.test(userAgent));
    if (automation) {
      const [label] = automation;
      classification = "likely_automation";
      classificationConfidence = 91;
      automationConfidence = 94;
      riskScore = 12;
      userAgentLabel = label;
      evidence.push(`Automation-oriented client identified: ${label}`);
    }
  }

  if (EXPLOIT_PROBE.test(path)) {
    if (!identity) {
      classification = "likely_automation";
      classificationConfidence = Math.max(classificationConfidence, 97);
    }
    automationConfidence = Math.max(automationConfidence, 98);
    riskScore = Math.max(riskScore, 86);
    evidence.push("Common exploit-probe route requested");
  }

  if (CRAWLER_TRAP.test(path)) {
    if (!identity) {
      classification = "likely_automation";
      classificationConfidence = Math.max(classificationConfidence, 92);
    }
    automationConfidence = Math.max(automationConfidence, 94);
    riskScore = Math.max(riskScore, 28);
    evidence.push(
      "Hidden crawler trap requested",
      "Trap access indicates automation but is not malicious by itself",
    );
  }

  if (input.signaturePresented && !identity) {
    evidence.push("HTTP message signature presented; identity not yet verified");
  }
  if (input.agentCredentialPresented) {
    evidence.push("Agent credential presented; authentication pending");
  }
  if (input.browserNavigation) {
    evidence.push("Browser navigation headers received");
  } else if (!crawler) {
    evidence.push("No normal browser navigation headers received");
  }

  return {
    classification,
    classificationConfidence,
    automationConfidence,
    riskScore,
    userAgentLabel,
    identity,
    evidence,
  };
}

function inputFromRequest(request) {
  const url = new URL(request.url);
  const headers = request.headers;
  return {
    userAgent: headers.get("user-agent") || "",
    path: url.pathname,
    browserNavigation: headers.get("sec-fetch-mode") === "navigate",
    signaturePresented: Boolean(headers.get("signature") || headers.get("signature-input")),
    agentCredentialPresented: Boolean(headers.get("authorization")),
  };
}

function classificationForIdentity(identity) {
  if (!identity) return null;
  if (identity.type === "agent" && identity.verified) return "verified_agent";
  if (identity.type === "bot" && identity.verified) return "verified_bot";
  if (identity.type === "bot") return "known_crawler";
  if (identity.type === "human" && identity.verified) return "human";
  return null;
}

function mergeProviderResult(inspection, providerResult) {
  if (!providerResult) return inspection;
  const identity = strongerIdentity(inspection.identity, providerResult.identity);
  const identityClassification = classificationForIdentity(identity);
  const classification = identityClassification || providerResult.classification || inspection.classification;
  const classificationConfidence = providerResult.classificationConfidence == null
    ? inspection.classificationConfidence
    : Math.max(inspection.classificationConfidence, clamp(providerResult.classificationConfidence));
  const automationConfidence = providerResult.automationConfidence == null
    ? inspection.automationConfidence
    : Math.max(inspection.automationConfidence, clamp(providerResult.automationConfidence));
  const riskScore = clamp(inspection.riskScore + Number(providerResult.riskDelta || 0));
  const evidence = [...new Set([
    ...inspection.evidence,
    ...(providerResult.evidence || []),
  ])];

  return {
    ...inspection,
    classification,
    classificationConfidence,
    automationConfidence,
    riskScore,
    userAgentLabel: identity?.name || inspection.userAgentLabel,
    identity,
    evidence,
  };
}

export function createDoorman(options = {}) {
  const knownCrawlers = [...DEFAULT_KNOWN_CRAWLERS, ...(options.knownCrawlers || [])];
  const automationClients = [...DEFAULT_AUTOMATION_CLIENTS, ...(options.automationClients || [])];
  const identityProviders = [...(options.identityProviders || [])];

  return Object.freeze({
    mode: options.mode || "observe",
    inspect(input) {
      return initialInspection(input, knownCrawlers, automationClients);
    },
    async inspectRequest(request, context = {}) {
      const input = { ...inputFromRequest(request), ...(context.input || {}) };
      let inspection = initialInspection(input, knownCrawlers, automationClients);
      for (const provider of identityProviders) {
        try {
          const result = await provider({ request, context, input, inspection });
          inspection = mergeProviderResult(inspection, result);
        } catch {
          inspection = mergeProviderResult(inspection, {
            evidence: ["An identity provider was unavailable; inspection continued without it"],
          });
        }
      }
      return inspection;
    },
  });
}

const defaultDoorman = createDoorman();

export function classifyInitialDoormanRequest(input) {
  return defaultDoorman.inspect(input);
}

export function browserLabel(userAgent) {
  if (/Edg\//i.test(userAgent)) return "Edge";
  if (/Chrome\//i.test(userAgent)) return "Chrome";
  if (/Firefox\//i.test(userAgent)) return "Firefox";
  if (/Safari\//i.test(userAgent) && !/Chrome\//i.test(userAgent)) return "Safari";
  if (/bot|crawler|spider/i.test(userAgent)) return "Unrecognized crawler";
  return userAgent ? "Unknown client" : "No user agent";
}

export function riskBand(score) {
  if (score >= 80) return "high";
  if (score >= 35) return "medium";
  return "low";
}

export function classificationLabel(classification) {
  return {
    human: "Human",
    verified_agent: "Verified Agent",
    verified_bot: "Verified Bot",
    known_crawler: "Known Crawler",
    likely_automation: "Likely Automation",
    unknown: "Unknown",
  }[classification] || "Unknown";
}

export function recommendationForRisk(score) {
  if (score >= 80) return "Block this visitor temporarily";
  if (score >= 55) return "Rate limit this visitor";
  if (score >= 30) return "Review this visitor";
  return "Allow and observe";
}

export {
  createCloudflareIdentityProvider,
  createRegistryIdentityProvider,
  createWebBotAuthIdentityProvider,
  fetchCloudflareRadarDirectory,
  normalizeIdentityEvidence,
  strongerIdentity,
};
