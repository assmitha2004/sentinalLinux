// Agent-supplied free-form objects are stored as Mixed. Keys containing "." or starting with "$"
// are rewritten so they can never be interpreted as Mongo paths/operators.
export function sanitizeKeys(value, depth = 0) {
  if (depth > 20) return null;
  if (Array.isArray(value)) return value.map((v) => sanitizeKeys(v, depth + 1));
  if (value && typeof value === 'object' && !(value instanceof Date)) {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k.replace(/^\$/, '_').replace(/\./g, '_')] = sanitizeKeys(v, depth + 1);
    return out;
  }
  return value;
}
