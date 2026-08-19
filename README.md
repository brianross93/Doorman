# Doorman

Doorman is an explainable traffic classifier for small websites. It keeps two questions separate:

1. What is visiting the site: a human, verified agent, known crawler, likely automation, or an unknown client?
2. Is the visitor behaving in a risky way?

The package uses deterministic rules. It does not claim that all automation is harmful, and it does not put a language model in the blocking path.

## Install

Install the current open-source package directly from GitHub:

```sh
npm install github:brianross93/Doorman
```

After the package is published to the npm registry:

```sh
npm install doorman-traffic
```

## Inspect a request

```js
import { createDoorman } from "doorman-traffic";

const doorman = createDoorman({ mode: "observe" });
const result = doorman.inspect({
  userAgent: request.headers.get("user-agent"),
  path: new URL(request.url).pathname,
  browserNavigation: request.headers.get("sec-fetch-mode") === "navigate",
});
```

The result contains the classification, confidence, automation confidence, risk score, evidence, and a readable client label. Your application decides how to store sessions and whether to enforce a policy.

## Identity and risk are separate

Doorman records identity assurance independently from behavior:

- `self_declared`: a recognized user-agent string. Easy to spoof.
- `directory_listed`: a user agent matches a known bot directory. This identifies a claim, not the request.
- `provider_attested`: a trusted edge provider identifies a verified bot or signed agent.
- `cryptographic`: the request passed Web Bot Auth signature verification with a trusted public key.

A verified agent can still behave badly. A crawler can be legitimate and low risk. An unknown client can be harmless. Doorman does not lower a risk score just because a client claims a familiar identity.

## Identity providers

Use one or more providers when you inspect the original `Request`:

```js
import {
  createDoorman,
  createRegistryIdentityProvider,
} from "doorman-traffic";

const directory = createRegistryIdentityProvider([
  {
    name: "Community Research Crawler",
    operator: "Community Lab",
    purpose: "research",
    kind: "BOT",
    userAgentPatterns: ["CommunityResearchBot/*"],
  },
]);

const doorman = createDoorman({ identityProviders: [directory] });
const result = await doorman.inspectRequest(request);
```

### Web Bot Auth

Doorman uses the open-source `web-bot-auth` verifier. The host supplies a trusted public-key resolver:

```js
import {
  createDoorman,
  createWebBotAuthIdentityProvider,
} from "doorman-traffic";

const webBotAuth = createWebBotAuthIdentityProvider({
  async resolveKey({ keyid, signatureAgent }) {
    const record = await trustedDirectory.lookup({ keyid, signatureAgent });
    if (!record) return null;
    return {
      jwk: record.publicJwk,
      identity: {
        type: "agent",
        name: record.name,
        operator: record.operator,
        purpose: record.purpose,
      },
    };
  },
});

const doorman = createDoorman({ identityProviders: [webBotAuth] });
const result = await doorman.inspectRequest(request);
```

The core package does not fetch an arbitrary `Signature-Agent` URL during a request. The host must validate and cache key directories, which avoids adding an unsafe server-side fetch path.

### Cloudflare

If the application runs in a Cloudflare environment, Doorman can consume trusted Bot Management request metadata:

```js
import {
  createCloudflareIdentityProvider,
  createDoorman,
} from "doorman-traffic";

const cloudflare = createCloudflareIdentityProvider({ trusted: true });
const doorman = createDoorman({ identityProviders: [cloudflare] });
const result = await doorman.inspectRequest(request, {
  cloudflare: request.cf,
});
```

Set `trusted: true` only when the metadata comes from the platform request object. Do not copy untrusted HTTP headers into this adapter.

Cloudflare Radar also publishes a verified-bot directory. `fetchCloudflareRadarDirectory` can download a snapshot with a Cloudflare API token. Pass that snapshot to `createRegistryIdentityProvider`; do not call Radar on every visitor request.

## Optional browser beacon

```js
import { startDoormanBeacon } from "doorman-traffic/client";

const stop = startDoormanBeacon({ endpoint: "/api/doorman/beacon" });
```

The beacon sends only event counts, session duration, page visibility, and the browser's `webdriver` flag. It does not capture typed text or pointer coordinates. A missing beacon is evidence, not proof of automation.

## Product boundary

This package owns classification, identity-provider adapters, risk scoring, route shaping, evidence, and the optional browser beacon. The host application owns storage, trusted key-directory policy, dashboards, notifications, and enforcement. This keeps the engine reusable without requiring a specific database, framework, edge provider, or hosted service.

## Safety defaults

- Observe first.
- Explain every classification.
- Keep identity separate from risk.
- Treat a self-declared user agent as evidence, not proof.
- Resolve signed-agent keys from a trusted, validated directory.
- Never collect request bodies, credentials, typed keys, or exact pointer coordinates.

## License

MIT
