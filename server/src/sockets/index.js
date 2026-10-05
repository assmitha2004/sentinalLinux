// Socket.IO (spec §41). Clients authenticate with their JWT; events are broadcast to the
// "dashboard" room and to per-host rooms the client joins.
import { Server } from 'socket.io';
import { config } from '../config/index.js';
import { userFromToken } from '../middleware/auth.js';
import { logger } from '../utils/logger.js';

const log = logger('socket');
let io = null;

export function initSockets(httpServer) {
  io = new Server(httpServer, { cors: { origin: config.corsOrigins, credentials: true }, maxHttpBufferSize: 1e5 });
  io.use(async (socket, next) => {
    const user = await userFromToken(socket.handshake.auth?.token).catch(() => null);
    if (!user) return next(new Error('unauthorized'));
    socket.data.user = { id: String(user._id), role: user.role };
    return next();
  });
  io.on('connection', (socket) => {
    socket.join('dashboard');
    socket.on('host:subscribe', (hostId) => typeof hostId === 'string' && /^[a-f0-9]{24}$/.test(hostId) && socket.join(`host:${hostId}`));
    socket.on('host:unsubscribe', (hostId) => typeof hostId === 'string' && socket.leave(`host:${hostId}`));
  });
  log.info('socket.io ready');
  return io;
}

// Events: metric:update security:alert finding:new host:online host:offline host:status
//         scan:started scan:progress scan:completed host:snapshot
export function emit(event, payload, hostId) {
  if (!io) return;
  const body = hostId ? { hostId: String(hostId), ...payload } : payload;
  // Snapshots are large: only clients viewing that host get them.
  if (event === 'host:snapshot') io.to(`host:${hostId}`).emit(event, body);
  else io.to('dashboard').emit(event, body);
}

export const closeSockets = () => io?.close();
