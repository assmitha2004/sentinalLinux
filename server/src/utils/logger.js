// Structured JSON logs (spec §67) with secret redaction.
const SECRET = /(token|secret|password|api[_-]?key|authorization)(["'=:\s]+)([^\s"',}]+)/gi;
function log(level, component, message, extra = {}) {
  const line = { timestamp: new Date().toISOString(), level, component, message: String(message).replace(SECRET, '$1$2[REDACTED]'), ...extra };
  (level === 'ERROR' ? console.error : console.log)(JSON.stringify(line));
}
export const logger = (component) => ({
  info: (m, e) => log('INFO', component, m, e),
  warn: (m, e) => log('WARN', component, m, e),
  error: (m, e) => log('ERROR', component, m, e),
});
