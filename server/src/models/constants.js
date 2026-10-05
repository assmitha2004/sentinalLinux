export const SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
export const SEVERITY_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
export const ROLES = ['ADMIN', 'ANALYST', 'VIEWER'];
export const SCAN_TYPES = ['QUICK', 'STANDARD', 'FULL', 'BENCHMARK', 'NETWORK', 'PROCESS', 'FILESYSTEM'];
export const FINDING_STATUS = ['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE'];
