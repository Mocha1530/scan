import { FastifyInstance, RegisterOptions } from 'fastify';

const routes = async (fastify: FastifyInstance, options: RegisterOptions) => {
  fastify.get('/', async (request: any, reply: any) => {
    reply.status(200).send('Welcome to Utils!');
  });
};

export default routes;
