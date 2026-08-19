export type DoormanBeaconOptions = {
  endpoint?: string;
  initialDelayMs?: number;
  maxEvents?: number;
};

export function startDoormanBeacon(options?: DoormanBeaconOptions): () => void;
