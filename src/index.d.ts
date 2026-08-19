export type DoormanClassification =
  | "human"
  | "verified_agent"
  | "known_crawler"
  | "likely_automation"
  | "unknown";

export type DoormanMode = "observe" | "enforce";
export type DoormanRule = readonly [label: string, pattern: RegExp];

export type DoormanInput = {
  userAgent?: string;
  path?: string;
  browserNavigation?: boolean;
  signaturePresented?: boolean;
  agentCredentialPresented?: boolean;
};

export type DoormanInspection = {
  classification: DoormanClassification;
  classificationConfidence: number;
  automationConfidence: number;
  riskScore: number;
  userAgentLabel: string;
  evidence: string[];
};

export const DOORMAN_CLASSIFICATIONS: readonly DoormanClassification[];

export function createDoorman(options?: {
  mode?: DoormanMode;
  knownCrawlers?: DoormanRule[];
  automationClients?: DoormanRule[];
}): {
  readonly mode: DoormanMode;
  inspect(input: DoormanInput): DoormanInspection;
};

export function classifyInitialDoormanRequest(input: DoormanInput): DoormanInspection;
export function normalizeDoormanPath(value: unknown): string;
export function routeShape(value: unknown): string;
export function browserLabel(userAgent: string): string;
export function riskBand(score: number): "low" | "medium" | "high";
export function classificationLabel(classification: string): string;
export function recommendationForRisk(score: number): string;
