import sharp from 'sharp';
import { supabase } from '../lib/supabase';
import { ScamImageRecord } from '../models';

async function computePHash(buffer: Buffer): Promise<bigint> {
  const data = await sharp(buffer)
    .resize(9, 8, { fit: 'fill' })
    .greyscale()
    .raw()
    .toBuffer();

  let hash = 0n;
  for (let row = 0; row < 8; row++) {
    for (let col = 0; col < 8; col++) {
      const left = data[row * 9 + col];
      const right = data[row * 9 + col + 1];
      if (left < right) {
        hash |= 1n << BigInt(row * 8 + col);
      }
    }
  }
  return hash;
}

async function findExactMatch(sha256: string): Promise<ScamImageRecord | null> {
  const { data, error } = await supabase
    .from('scam_images')
    .select('id, sha256, phash, is_scam, metadata')
    .eq('sha256', sha256)
    .maybeSingle();

  if (error || !data) return null;
  return {
    id: data.id,
    sha256: data.sha256,
    phash: BigInt(data.phash),
    is_scam: data.is_scam,
    metadata: data.metadata,
  };
}

async function findSimilarPhash(
  phash: bigint,
  threshold: number,
): Promise<ScamImageRecord | null> {
  const { data, error } = await supabase.rpc('find_similar_phash', {
    target_phash: phash.toString(),
    threshold: threshold,
  });

  if (error || !data || data.length === 0) return null;

  const row = data[0];
  return {
    id: row.id,
    sha256: row.sha256,
    phash: BigInt(row.phash),
    is_scam: row.is_scam,
    metadata: row.metadata,
  };
}

async function insertNewImage(
  sha256: string,
  phash: bigint,
  isScam: boolean,
  imageUrl?: string,
): Promise<void> {
  const { error } = await supabase.from('scam_images').insert({
    sha256: sha256,
    phash: phash.toString(),
    is_scam: isScam,
    metadata: {
      detected_at: new Date().toISOString(),
      detection_method: imageUrl ? 'manual_upload' : 'api_submission',
      image_url: imageUrl || null,
    },
  });

  if (error) throw new Error(`Supabase insert failed: ${error.message}`);
}

export { computePHash, findExactMatch, findSimilarPhash, insertNewImage };
