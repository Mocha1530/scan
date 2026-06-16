import { FastifyReply, FastifyInstance, RegisterOptions, FastifyRequest } from 'fastify';

import cache from '../../utils/cache';
import { redis, REDIS_TTL, supabase } from '../../main';
import Redis from 'ioredis';
import { createHash } from 'crypto';
import { computePHash, findExactMatch, insertNewImage } from '../../utils/functions';

const routes = async (fastify: FastifyInstance, options: RegisterOptions) => {
  // fastify.get("/", ())

  fastify.post('/', async (request: FastifyRequest, reply: FastifyReply) => {
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer')) {
      return reply.status(401).send({ error: 'Missing or invalid Authorization header' });
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

        const existing = await findExactMatch(sha256);
        if (existing) {
          if (existing.is_scam) {
            results.push({
              image: imageInput,
              status: 'already_exists',
              is_scam: existing.is_scam,
              id: existing.id,
            });
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
            results.push({
              image: imageInput,
              status: 'updated_to_scam',
              id: existing.id,
            });
          }
        } else {
          await insertNewImage(sha256, phash, true, imageInput);
          results.push({ image: imageInput, status: 'inserted' });
        }

        if (useCache) {
          await cache.set(redis as Redis, cacheKey, () => ({ is_scam: true }), REDIS_TTL);
        }
      } catch (err: any) {
        results.push({ image: imageInput, error: err.message });
      }
    }

    return reply.send({ results });
  });
};

export default routes;
