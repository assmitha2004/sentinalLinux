import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

const log = logger('http');

// Sanitized errors (spec §77): no stack traces leave the server in production.
// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, _next) {
  if (err?.type === 'entity.too.large') {
    return res.status(413).json({ success: false, error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body too large' } });
  }
  if (err?.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, error: { code: 'BAD_JSON', message: 'Malformed JSON' } });
  }
  if (err?.code === 11000) {
    return res.status(409).json({ success: false, error: { code: 'CONFLICT', message: 'Resource already exists' } });
  }
  const status = err.status || 500;
  if (status >= 500) log.error(err.message, { path: req.path, stack: config.isProd ? undefined : err.stack });
  const body = { code: err.code || 'INTERNAL_ERROR', message: status >= 500 && config.isProd ? 'Internal server error' : err.message };
  if (err.details) body.details = err.details;
  return res.status(status).json({ success: false, error: body });
}

export const notFoundHandler = (req, res) => res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: `Route ${req.method} ${req.path} not found` } });
