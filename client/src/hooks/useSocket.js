import { useEffect, useRef } from 'react';
import { getSocket } from '../services/socket.js';

/** Subscribe to socket events: handlers = { 'metric:update': fn, ... }. Optionally join a host room. */
export function useSocket(handlers, hostId) {
  const ref = useRef(handlers);
  ref.current = handlers;
  useEffect(() => {
    const s = getSocket();
    if (!s) return undefined;
    const names = Object.keys(ref.current);
    const bound = names.map((n) => [n, (p) => ref.current[n]?.(p)]);
    bound.forEach(([n, fn]) => s.on(n, fn));
    if (hostId) s.emit('host:subscribe', hostId);
    return () => {
      bound.forEach(([n, fn]) => s.off(n, fn));
      if (hostId) s.emit('host:unsubscribe', hostId);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hostId]);
}
