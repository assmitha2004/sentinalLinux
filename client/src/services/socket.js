import { io } from 'socket.io-client';
import { DEMO_MODE, tokenStore } from './api.js';

let socket = null;

export function getSocket() {
  if (DEMO_MODE) return null;
  if (socket) return socket;
  const token = tokenStore.get();
  if (!token) return null;
  socket = io(import.meta.env.VITE_SOCKET_URL || 'http://localhost:5000', { auth: { token }, transports: ['websocket', 'polling'] });
  return socket;
}

export function closeSocket() {
  socket?.close();
  socket = null;
}
