import { AppError } from '../utils/http.js';

export const validate = (schema, where = 'body') => (req, _res, next) => {
  const r = schema.safeParse(req[where]);
  if (!r.success) {
    return next(new AppError(400, 'VALIDATION_ERROR', 'Invalid request',
      r.error.issues.slice(0, 10).map((i) => ({ path: i.path.join('.'), message: i.message }))));
  }
  if (where === 'body') req.body = r.data;
  else req.validated = r.data;
  return next();
};

export const objectId = (req, _res, next) => {
  if (!/^[a-f0-9]{24}$/i.test(req.params.id || '')) return next(new AppError(400, 'VALIDATION_ERROR', 'Invalid id'));
  return next();
};
