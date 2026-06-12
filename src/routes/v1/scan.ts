import { FastifyReply, FastifyInstance, RegisterOptions, FastifyRequest } from 'fastify';

import cache from '../../utils/cache';
import { redis, REDIS_TTL } from '../../main';
import { createClient } from '@supabase/supabase-js';
import { GoogleGenAI, Type } from '@google/genai';
import Redis from 'ioredis';
import sharp from 'sharp';
import { createHash } from 'crypto';

const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!);

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

const scamSchema = {
  type: Type.OBJECT,
  properties: {
    isScam: { type: Type.BOOLEAN },
    confidence: { type: Type.NUMBER },
    reasoning: { type: Type.STRING },
  },
  required: ['isScam', 'confidence'],
};

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

interface ScamImageRecord {
  id: number;
  sha256: string;
  phash: bigint;
  is_scam: boolean;
}

async function findExactMatch(sha256: string): Promise<ScamImageRecord | null> {
  const { data, error } = await supabase
    .from('scam_images')
    .select('id, sha256, phash, is_scam')
    .eq('sha256', sha256)
    .maybeSingle();

  if (error || !data) return null;
  return {
    id: data.id,
    sha256: data.sha256,
    phash: BigInt(data.phash),
    is_scam: data.is_scam,
  };
}

async function findSimilarPhash(
  phash: bigint,
  threshold: number,
): Promise<ScamImageRecord | null> {
  const { data, error } = await supabase
    .from('scam_images')
    .select('id, sha256, phash, is_scam')
    .limit(50);

  if (error || !data) return null;

  let bestMatch: ScamImageRecord | null = null;
  let bestDistance = threshold;

  for (const row of data) {
    const rowPhash = BigInt(row.phash);
    const xor = phash ^ rowPhash;

    let distance = 0;
    let n = xor;
    while (n > 0n) {
      distance += Number(n & 1n);
      n >>= 1n;
    }
    if (distance < bestDistance) {
      bestDistance = distance;
      bestMatch = {
        id: row.id,
        sha256: row.sha256,
        phash: row.phash,
        is_scam: row.is_scam,
      };
      if (distance === 0) break;
    }
  }
  return bestMatch;
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
      detection_method: 'api_submission',
      image_url: imageUrl,
    },
  });

  if (error) throw new Error(`Supabase insert failed: ${error.message}`);
}

const routes = async (fastify: FastifyInstance, options: RegisterOptions) => {
  // fastify.get("/", ())

  fastify.post('/', async (request: FastifyRequest, reply: FastifyReply) => {
    const { images } = request.body as { images: string[] }; // array of URLs or base64
    if (!images || !Array.isArray(images)) {
      return reply.status(400).send({ error: 'images array required' });
    }

    const results = [];

    for (const imageInput of images) {
      try {
        let buffer: Buffer;
        if (imageInput.startsWith('http')) {
          const resp = await fetch(imageInput);
          buffer = Buffer.from(await resp.arrayBuffer());
        } else if (imageInput.startsWith('data:image')) {
          buffer = Buffer.from(imageInput.split(',')[1], 'base64');
        } else {
          throw new Error('Unsupported image format');
        }

        const sha256 = createHash('sha256').update(buffer).digest('hex');
        const phash = await computePHash(buffer);

        const cacheKey = `scan:${sha256}`;
        const useCache = redis ? true : false;

        if (useCache) {
          const cached = await cache.get<{ is_scam: boolean }>(redis as Redis, cacheKey);
          if (cached) {
            results.push({
              image: imageInput,
              is_scam: cached.is_scam,
              match_type: 'cached',
            });
            continue;
          }
        }

        let record = await findExactMatch(sha256);
        if (record) {
          if (useCache) {
            await cache.set(
              redis as Redis,
              cacheKey,
              () => ({ is_scam: record?.is_scam }),
              REDIS_TTL,
            );
          }
          results.push({
            image: imageInput,
            is_scam: record.is_scam,
            match_type: 'exact',
          });
          continue;
        }

        const similar = await findSimilarPhash(phash, 10);
        if (similar) {
          results.push({
            image: imageInput,
            is_scam: similar.is_scam,
            match_type: 'variant',
          });
          continue;
        }

        const isScam = await isScamImage(buffer);
        if (isScam) {
          await insertNewImage(sha256, phash, isScam, imageInput);
        }
        if (useCache) {
          await cache.set(
            redis as Redis,
            cacheKey,
            () => ({ is_scam: isScam }),
            REDIS_TTL,
          );
        }
        results.push({ image: imageInput, is_scam: isScam, match_type: 'new' });
      } catch (err: any) {
        results.push({ image: imageInput, error: err.message });
      }
    }

    return reply.send({ results });
  });
};

async function isScamImage(buffer: Buffer): Promise<boolean> {
  if (!process.env.GEMINI_API_KEY) {
    return false;
  }

  try {
    const base64Image = buffer.toString('base64');
    const mimeType = 'image/png';

    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: [
        { inlineData: { data: base64Image, mimeType } },
        'Analyze this image for scam indicators: crypto giveaway, MrBeast impersonation, fake QR codes, or phishing. Return JSON.',
      ],
      config: {
        responseMimeType: 'application/json',
        responseSchema: scamSchema,
        temperature: 0.1,
      },
    });

    if (!response.text) {
      throw new Error('Gemini returned an empty response');
    }

    const result = JSON.parse(response.text);
    return result.isScam && result.confidence > 0.7;
  } catch (err) {
    console.error('Gemini failed:', err);
    return false;
  }
}

export default routes;
