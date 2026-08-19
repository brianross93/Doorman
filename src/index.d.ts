export type DoormanClassification =
  | "human"
  | "verified_agent"
  | "verified_bot"
  | "known_crawler"
  | "likely_automation"
  | "unknown";

export type DoormanMode = "observe" | "enforce";
export type DoormanRule = readonly [
  label: string,
  pattern: RegExp,
  purpose?: string,
];
export type DoormanIdentityType = "human" | "agent" | "bot" | "unknown";
export type DoormanIdentityAssurance =
  | "none"
  | "self_declared"
  | "directory_listed"
  | "provider_attested"
  | "cryptographic";

export type DoormanInput = {
  userAgent?: string;
  path?: string;
  browserNavigation?: boolean;
  signaturePresented?: boolean;
  agentCredentialPresented?: boolean;
};

export type DoormanIdentityEvidence = {
  type: DoormanIdentityType;
  name: string;
  operator: string | null;
  purpose: string;
  accessMode: string | null;
  assurance: DoormanIdentityAssurance;
  source: string;
  verified: boolean;
  signatureAgent: string | null;
};

export type DoormanInspection = {
  classification: DoormanClassification;
  classificationConfidence: number;
  automationConfidence: number;
  riskScore: number;
  userAgentLabel: string;
  identity: DoormanIdentityEvidence | null;
  evidence: string[];
};

export type DoormanIdentityProviderResult = {
  identity?: Partial<DoormanIdentityEvidence>;
  classification?: DoormanClassification;
  classificationConfidence?: number;
  automationConfidence?: number;
  riskDelta?: number;
  evidence?: string[];
} | null;

export type DoormanIdentityProvider = (input: {
  request: Request;
  context: Record<string, unknown>;
  input: DoormanInput;
  inspection: DoormanInspection;
}) => Promise<DoormanIdentityProviderResult> | DoormanIdentityProviderResult;

export type DirectoryIdentityEntry = {
  name: string;
  operator?: string;
  category?: string;
  purpose?: string;
  kind?: string;
  slug?: string;
  accessMode?: string;
  signatureAgentUrl?: string;
  userAgentPatterns?: Array<string | RegExp>;
  userAgents?: Array<string | RegExp>;
};

export type WebBotAuthKeyResolution = {
  jwk: JsonWebKey;
  identity?: {
    type?: DoormanIdentityType;
    name?: string;
    operator?: string;
    purpose?: string;
    accessMode?: string;
  };
};

export const DOORMAN_CLASSIFICATIONS: readonly DoormanClassification[];

export function createDoorman(options?: {
  mode?: DoormanMode;
  knownCrawlers?: DoormanRule[];
  automationClients?: DoormanRule[];
  identityProviders?: DoormanIdentityProvider[];
}): {
  readonly mode: DoormanMode;
  inspect(input: DoormanInput): DoormanInspection;
  inspectRequest(
    request: Request,
    context?: Record<string, unknown> & { input?: DoormanInput },
  ): Promise<DoormanInspection>;
};

export function createRegistryIdentityProvider(
  entries?: DirectoryIdentityEntry[],
  options?: { source?: string },
): DoormanIdentityProvider;

export function fetchCloudflareRadarDirectory(options: {
  apiToken: string;
  fetch?: typeof fetch;
  limit?: number;
  endpoint?: string;
  signal?: AbortSignal;
}): Promise<DirectoryIdentityEntry[]>;

export function createCloudflareIdentityProvider(options?: {
  trusted?: boolean;
  getMetadata?: (
    request: Request,
    context: Record<string, unknown>,
  ) => unknown | Promise<unknown>;
}): DoormanIdentityProvider;

export function createWebBotAuthIdentityProvider(options: {
  resolveKey: (details: {
    keyid: string;
    signatureAgent: string | null;
    request: Request;
  }) => WebBotAuthKeyResolution | null | Promise<WebBotAuthKeyResolution | null>;
}): DoormanIdentityProvider;

export function normalizeIdentityEvidence(
  identity?: Partial<DoormanIdentityEvidence>,
): DoormanIdentityEvidence;
export function strongerIdentity(
  left?: Partial<DoormanIdentityEvidence> | null,
  right?: Partial<DoormanIdentityEvidence> | null,
): DoormanIdentityEvidence | null;
export function classifyInitialDoormanRequest(input: DoormanInput): DoormanInspection;
export function normalizeDoormanPath(value: unknown): string;
export function routeShape(value: unknown): string;
export function browserLabel(userAgent: string): string;
export function riskBand(score: number): "low" | "medium" | "high";
export function classificationLabel(classification: string): string;
export function recommendationForRisk(score: number): string;
