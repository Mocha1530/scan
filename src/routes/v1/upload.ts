import { FastifyReply, FastifyInstance, RegisterOptions, FastifyRequest } from 'fastify';
import pLimit from 'p-limit';

import { supabase } from '../../lib/supabase';
import cache from '../../utils/cache';
import { redis, REDIS_TTL } from '../../main';
import Redis from 'ioredis';
import sharp from 'sharp';
import { createHash } from 'crypto';
import { computePHash, findExactMatch, insertNewImage } from '../../utils/functions';

const bodySchema = {
  type: 'object',
  required: ['images'],
  properties: {
    images: {
      type: 'array',
      items: { type: 'string' },
      maxItems: 20,
    },
  },
};

const routes = async (fastify: FastifyInstance, options: RegisterOptions) => {
  // fastify.get("/", ())

  fastify.post(
    '/',
    { schema: { body: bodySchema } },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const authHeader = request.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer')) {
        return reply
          .status(401)
          .send({ error: 'Missing or invalid Authorization header' });
      }
      const token = authHeader.split(' ')[1];
      const adminKey = process.env.ADMIN_API_KEY;
      if (!adminKey || token !== adminKey) {
        return reply.status(403).send({ error: 'Forbidden: invalid token' });
      }

      const { images } = request.body as { images: string[] }; // array of URLs or base64
      if (!images || !Array.isArray(images)) {
        return reply.status(400).send({ error: 'images array required' });
      }

      const uniqueMap = new Map<string, string>();
      for (const img of images) {
        if (!uniqueMap.has(img)) uniqueMap.set(img, img);
      }
      const uniqueImages = Array.from(uniqueMap.values());

      const limit = pLimit(5);
      const results = await Promise.all(
        uniqueImages.map((img) => limit(() => processImage(img))),
      );

      return reply.send({ results });
    },
  );
};

async function processImage(imageInput: string) {
  try {
    let buffer: Buffer;
    if (imageInput.startsWith('http')) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      try {
        const resp = await fetch(imageInput, { signal: controller.signal });
        clearTimeout(timeout);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        buffer = Buffer.from(await resp.arrayBuffer());
      } catch (err: any) {
        clearTimeout(timeout);
        throw new Error(`Download failed: ${err.message}`);
      }
    } else if (imageInput.startsWith('data:image')) {
      buffer = Buffer.from(imageInput.split(',')[1], 'base64');
    } else {
      throw new Error('Unsupported image format');
    }

    const { format } = await sharp(buffer).metadata();
    if (!format || !['jpeg', 'png', 'webp', 'gif'].includes(format)) {
      throw new Error(`Unsupported image format: ${format}`);
    }

    const sha256 = createHash('sha256').update(buffer).digest('hex');
    const phash = await computePHash(buffer);

    const cacheKey = `scan:${sha256}`;
    const useCache = redis ? true : false;

    const existing = await findExactMatch(sha256);
    if (existing) {
      if (existing.is_scam) {
        return {
          image: imageInput,
          status: 'already_exists',
          is_scam: existing.is_scam,
          id: existing.id,
        };
      } else {
        const { error } = await supabase
          .from('scam_images')
          .update({
            is_scam: true,
            metadata: {
              ...existing.metadata,
              updated_by_upload: new Date().toISOString(),
              image_url: imageInput,
            },
          })
          .eq('sha256', sha256);

        if (error) throw new Error(`Failed to update: ${error.message}`);
        if (useCache) {
          await cache.set(redis as Redis, cacheKey, () => ({ is_scam: true }), REDIS_TTL);
        }
        return {
          image: imageInput,
          status: 'updated_to_scam',
          id: existing.id,
        };
      }
    } else {
      await insertNewImage(sha256, phash, true, imageInput);
      if (useCache) {
        await cache.set(redis as Redis, cacheKey, () => ({ is_scam: true }), REDIS_TTL);
      }
      return { image: imageInput, status: 'inserted' };
    }
  } catch (err: any) {
    return { image: imageInput, error: err.message };
  }
}

export default routes;
