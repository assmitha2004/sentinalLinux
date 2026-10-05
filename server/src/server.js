import http from 'node:http';
import { createApp } from './app.js';
import { config } from './config/index.js';
import { connectDb, disconnectDb } from './config/db.js';
import { startJobs, stopJobs } from './services/jobs.js';
import { closeSockets, initSockets } from './sockets/index.js';
import { logger } from './utils/logger.js';

const log = logger('server');

async function main() {
  await connectDb(config.MONGODB_URI);
  const server = http.createServer(createApp());
  initSockets(server);
  startJobs();
  server.listen(config.PORT, () => log.info(`SentinelAI API listening on :${config.PORT}`, { env: config.NODE_ENV, ai: config.aiEnabled }));
  const shutdown = async (sig) => {
    log.info(`${sig} received, shutting down`);
    stopJobs();
    closeSockets();
    server.close();
    await disconnectDb();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((e) => {
  log.error(`startup failed: ${e.message}`);
  process.exit(1);
});
