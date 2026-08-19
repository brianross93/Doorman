const DEFAULT_KNOWN_CRAWLERS = [
  ["OAI-SearchBot", /\bOAI-SearchBot\b/i],
  ["ChatGPT-User", /\bChatGPT-User\b/i],
  ["GPTBot", /\bGPTBot\b/i],
  ["ClaudeBot", /\bClaudeBot\b/i],
  ["Claude-SearchBot", /\bClaude-SearchBot\b/i],
  ["PerplexityBot", /\bPerplexityBot\b/i],
  ["Googlebot", /\bGooglebot\b/i],
  ["bingbot", /\bbingbot\b/i],
  ["Applebot", /\bApplebot\b/i],
  ["Amazonbot", /\bAmazonbot\b/i],
  ["Meta crawler", /\b(?:Meta-ExternalAgent|FacebookBot)\b/i],
  ["Bytespider", /\bBytespider\b/i],
  ["Common Crawl", /\bCCBot\b/i],
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

export const DOORMAN_CLASSIFICATIONS = Object.freeze([
  "human",
  "verified_agent",
  "known_crawler",
  "likely_automation",
  "unknown",
]);

export function normalizeDoormanPath(value) {
  const path = String(value || "/").split(/[?#]/, 1)[0] || "/";
  return (path.startsWith("/") ? path : `/${path}`).slice(0, 240);
}

export function routeShape(value) {
  return normalizeDoormanPath(value)
    .replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, ":id")
    .replace(/\/\d{2,}(?=\/|$)/g, "/:id");
}

function inspectWithRules(input, knownCrawlers, automationClients) {
  const userAgent = String(input.userAgent || "").slice(0, 320);
  const path = normalizeDoormanPath(input.path);
  const evidence = [];

  for (const [label, pattern] of knownCrawlers) {
    if (pattern.test(userAgent)) {
      return {
        classification: "known_crawler",
        classificationConfidence: 98,
        automationConfidence: 100,
        riskScore: 4,
        userAgentLabel: label,
        evidence: [
          `Known crawler user agent: ${label}`,
          "User agent is evidence, not cryptographic proof",
        ],
      };
    }
  }

  for (const [label, pattern] of automationClients) {
    if (pattern.test(userAgent)) {
      return {
        classification: "likely_automation",
        classificationConfidence: 91,
        automationConfidence: 94,
        riskScore: 12,
        userAgentLabel: label,
        evidence: [`Automation-oriented client identified: ${label}`],
      };
    }
  }

  if (/\/(?:wp-admin|wp-login|phpmyadmin|\.env)(?:\/|$)|\/xmlrpc\.php$/i.test(path)) {
    return {
      classification: "likely_automation",
      classificationConfidence: 97,
      automationConfidence: 98,
      riskScore: 86,
      userAgentLabel: browserLabel(userAgent),
      evidence: ["Common exploit-probe route requested"],
    };
  }

  if (input.signaturePresented) {
    evidence.push("HTTP message signature presented; identity not yet verified");
  }
  if (input.agentCredentialPresented) {
    evidence.push("Agent credential presented; authentication pending");
  }
  if (input.browserNavigation) {
    evidence.push("Browser navigation headers received");
  } else {
    evidence.push("No normal browser navigation headers received");
  }

  return {
    classification: "unknown",
    classificationConfidence: input.browserNavigation ? 58 : 45,
    automationConfidence: input.browserNavigation ? 24 : 56,
    riskScore: 5,
    userAgentLabel: browserLabel(userAgent),
    evidence,
  };
}

export function createDoorman(options = {}) {
  const knownCrawlers = [
    ...DEFAULT_KNOWN_CRAWLERS,
    ...(options.knownCrawlers || []),
  ];
  const automationClients = [
    ...DEFAULT_AUTOMATION_CLIENTS,
    ...(options.automationClients || []),
  ];

  return Object.freeze({
    mode: options.mode || "observe",
    inspect(input) {
      return inspectWithRules(input, knownCrawlers, automationClients);
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
