import { FastifyReply, FastifyInstance, RegisterOptions, FastifyRequest } from 'fastify';

import cache from '../../utils/cache';
import { redis, REDIS_TTL } from '../../../main';
import Redis from 'ioredis';
import sharp from 'sharp';
import { createHash } from 'crypto';

async function computePHash(buffer: Buffer): Promise<bigint> {
  const { data } = await sharp(buffer)
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
  /* TODO */
}
async function findSimilarPhash(
  phash: bigint,
  threshold: number,
): Promise<ScamImageRecord | null> {
  /* TODO */
}
async function insertNewImage(
  sha256: string,
  phash: bigint,
  isScam: boolean,
): Promise<void> {
  /* TODO */
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
        let cached = await cache.get<{ is_scam: boolean }>(redis, cacheKey);
        if (cached) {
          results.push({
            image: imageInput,
            is_scam: cached.is_scam,
            match_type: 'cached',
          });
          continue;
        }

        let record = await findExactMatch(sha256);
        if (record) {
          await cache.set(
            redis,
            cacheKey,
            () => ({ is_scam: record?.is_scam }),
            REDIS_TTL,
          );
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

        await insertNewImage(sha256, phash, isScam);
        await cache.set(redis, cacheKey, () => ({ is_scam: isScam }), REDIS_TTL);
        results.push({ image: imageInput, is_scam: isScam, match_type: 'new' });
      } catch (err: any) {
        results.push({ image: imageInput, error: err.message });
      }
    }

    return reply.send({ results });
  });
};

async function isScamImage(buffer: Buffer): Promise<boolean> {
  // TODO: Check for scam keywords via OCR
  return false;
}

export default routes;
