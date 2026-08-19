# RigorLoop Doorman

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
npm install @rigorloop/doorman
```

## Inspect a request

```js
import { createDoorman } from "@rigorloop/doorman";

const doorman = createDoorman({ mode: "observe" });
const result = doorman.inspect({
  userAgent: request.headers.get("user-agent"),
  path: new URL(request.url).pathname,
  browserNavigation: request.headers.get("sec-fetch-mode") === "navigate",
});
```

The result contains the classification, confidence, automation confidence, risk score, evidence, and a readable client label. Your application decides how to store sessions and whether to enforce a policy.

## Agent identity is an adapter

Doorman does not require a RigorLoop account and does not recognize RigorLoop API keys. A host site can connect any trusted identity system, including its own API keys or a Web Bot Auth verifier, then mark that traffic as a verified agent in its storage adapter. Unsigned traffic can still be classified by behavior, but it is never presented as cryptographically verified.

## Optional browser beacon

```js
import { startDoormanBeacon } from "@rigorloop/doorman/client";

const stop = startDoormanBeacon({ endpoint: "/api/doorman/beacon" });
```

The beacon sends only event counts, session duration, page visibility, and the browser's `webdriver` flag. It does not capture typed text or pointer coordinates. A missing beacon is evidence, not proof of automation.

## Product boundary

This package owns classification, risk scoring, route shaping, evidence, and the optional browser beacon. The host application owns storage, identity verification, dashboards, notifications, and enforcement. This keeps the engine reusable without requiring a vendor database, framework, or RigorLoop service.

## Safety defaults

- Observe first.
- Explain every classification.
- Keep identity separate from risk.
- Treat a self-declared user agent as evidence, not proof.
- Verify signed agent identities in a trusted application adapter.
- Never collect request bodies, credentials, typed keys, or exact pointer coordinates.

## License

MIT
