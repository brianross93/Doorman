import assert from "node:assert/strict";
import test from "node:test";
import { createDoormanAnalyst } from "../src/analyst.mjs";

test("the optional analyst uses the host API key and keeps responses stateless", async () => {
  let request;
  const analyst = createDoormanAnalyst({
    apiKey: "test-key",
    fetch: async (url, options) => {
      request = { url, options };
      return {
        ok: true,
        status: 200,
        headers: { get: () => "req_test" },
        async json() { return { output_text: "Review the high-risk sessions first." }; },
      };
    },
  });
  const result = await analyst.ask({
    snapshot: { totals: { sessions: 4 } },
    messages: [{ role: "user", content: "What needs attention?" }],
  });
  const body = JSON.parse(request.options.body);
  assert.equal(request.url, "https://api.openai.com/v1/responses");
  assert.equal(request.options.headers.Authorization, "Bearer test-key");
  assert.equal(body.model, "gpt-5.6-luna");
  assert.equal(body.store, false);
  assert.equal(result.answer, "Review the high-risk sessions first.");
});

test("the optional analyst requires a server-side API key", () => {
  assert.throws(() => createDoormanAnalyst({}), /server-side API key/);
});
