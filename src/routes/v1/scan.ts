import { FastifySchema, FastifyReply, FastifyInstance, RegisterOptions } from "fastify";

import { redis, REDIS_TTL } from "../../../main";
import Redis from "ioredis";

const routes = async (fastify: FastifyInstance, options: RegisterOptions) => {
  fastify.get("/", ())
}
