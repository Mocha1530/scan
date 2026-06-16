import { FastifyInstance, FastifyReply, FastifyRequest, RegisterOptions } from 'fastify';

import scan from './scan';
import upload from './upload';

const routes = async (fastify: FastifyInstance, options: RegisterOptions) => {
  fastify.register(scan, { prefix: '/scan' });
  fastify.register(upload, { prefix: '/upload' });

  fastify.get('/', async (_request: FastifyRequest, reply: FastifyReply) => {
    reply.status(200).send('Welcome to v1');
  });
};

export default routes;
