import { FastifyInstance, FastifyReply, FastifyRequest, RegisterOptions } from 'fastify';

import scan from './scan';

const routes = async (fastify: FastifyInstance, options: RegisterOptions) => {
  fastify.register(scan, { prefix: '/scan' });

  fastify.get('/', async (_request: FastifyRequest, reply: FastifyReply) => {
    reply.status(200).send('Welcome to v1');
  });
};

export default routes;
