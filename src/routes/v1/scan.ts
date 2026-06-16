import { FastifyReply, FastifyInstance, RegisterOptions, FastifyRequest } from 'fastify';
import pLimit from 'p-limit';

import cache from '../../utils/cache';
import { redis, REDIS_TTL } from '../../main';
import { GoogleGenAI, Type } from '@google/genai';
import Redis from 'ioredis';
import { createHash } from 'crypto';
import sharp from 'sharp';
import {
  computePHash,
  findExactMatch,
  findSimilarPhash,
  insertNewImage,
} from '../../utils/functions';

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
    {
      schema: { body: bodySchema },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
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
        uniqueImages.map((imageInput) => limit(() => processImage(imageInput))),
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

    const cacheKey = `scan:${sha256}`;
    const useCache = redis ? true : false;
    if (useCache) {
      const cached = await cache.get<{ is_scam: boolean }>(redis as Redis, cacheKey);
      if (cached !== null) {
        return {
          image: imageInput,
          is_scam: cached.is_scam,
          match_type: 'cached',
        };
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
      return {
        image: imageInput,
        is_scam: record.is_scam,
        match_type: 'exact',
      };
    }

    const phash = await computePHash(buffer);
    const similar = await findSimilarPhash(phash, 10);
    if (similar) {
      return {
        image: imageInput,
        is_scam: similar.is_scam,
        match_type: 'variant',
      };
    }

    const isScam = await isScamImage(buffer);
    if (isScam) {
      await insertNewImage(sha256, phash, isScam, imageInput);
    }
    if (useCache) {
      await cache.set(redis as Redis, cacheKey, () => ({ is_scam: isScam }), REDIS_TTL);
    }
    return { image: imageInput, is_scam: isScam, match_type: 'new' };
  } catch (err: any) {
    return { image: imageInput, error: err.message };
  }
}

async function isScamImage(buffer: Buffer): Promise<boolean | null> {
  if (!process.env.GEMINI_API_KEY) {
    return null;
  }

  try {
    const { format } = await sharp(buffer).metadata();
    const mimeType = format ? `image/${format}` : 'image/png';

    const base64Image = buffer.toString('base64');

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
    return null;
  }
}

export default routes;
