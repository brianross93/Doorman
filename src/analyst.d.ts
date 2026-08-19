export type DoormanAnalystMessage = {
  role: "user" | "assistant";
  content: string;
};

export type DoormanAnalystOptions = {
  apiKey: string;
  model?: string;
  endpoint?: string;
  fetch?: typeof fetch;
  maxOutputTokens?: number;
  timeoutMs?: number;
};

export function buildDoormanAnalystInstructions(snapshot: Record<string, unknown>): string;
export function extractDoormanAnalystText(payload: unknown): string;
export function createDoormanAnalyst(options: DoormanAnalystOptions): {
  readonly model: string;
  ask(input: {
    snapshot: Record<string, unknown>;
    messages: DoormanAnalystMessage[];
  }): Promise<{ answer: string; model: string; requestId: string | null }>;
};
