export interface ScamImageRecord {
  id: number;
  sha256: string;
  phash: bigint;
  is_scam: boolean;
  metadata: Record<string, any>;
}
