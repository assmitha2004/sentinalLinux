// Deterministic recommendation rules (spec §92). Used for the no-LLM fallback and to enrich
// findings. Every command is labelled READ-ONLY or MODIFYING (spec §73).
const R = (title, steps, verify, modifying) => ({ title, steps, verification: { mode: 'READ-ONLY', command: verify }, modifying, requiresAdminApproval: !!modifying });

export const RULES = {
  ssh_root_login: R('Disable direct root SSH login', ['Create/verify a non-root administrative account with sudo.',
    'Confirm you can log in with that account in a second session.', 'Set "PermitRootLogin no" in /etc/ssh/sshd_config.',
    'Validate with "sshd -t", then restart the SSH service.'],
  "sshd -T | grep -i permitrootlogin", "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sshd -t && systemctl restart ssh"),
  ssh_password_authentication: R('Prefer key-based SSH authentication', ['Review whether password authentication is required.',
    'Install public keys for every admin (ssh-copy-id).', 'Set "PasswordAuthentication no" once keys are verified.', 'Validate with "sshd -t" before restarting.'],
  "sshd -T | grep -i passwordauthentication", 'Edit /etc/ssh/sshd_config: PasswordAuthentication no'),
  ssh_empty_passwords: R('Forbid empty SSH passwords', ['Set "PermitEmptyPasswords no".'], 'sshd -T | grep -i permitemptypasswords', 'Edit /etc/ssh/sshd_config'),
  firewall_inactive: R('Enable a host firewall', ['List required inbound services (ss -tulpn).', 'Write an nftables ruleset that allows only those.',
    'Test from a second session before persisting.'], 'nft list ruleset', 'nft -f /etc/nftables.conf && systemctl enable --now nftables'),
  uid0_account: R('Investigate extra UID-0 account', ['Confirm whether the account is documented.', 'If not, treat the host as potentially compromised.'],
    "awk -F: '$3==0' /etc/passwd", 'usermod/userdel only after investigation'),
  empty_password: R('Lock accounts without passwords', ['Lock the account or set a strong password.'], 'passwd -S <user>', 'passwd -l <user>'),
  unexpected_suid: R('Review unexpected SUID/SGID binary', ['Check package ownership (dpkg -S).', 'Compare hash with a known-good copy.',
    'Remove the bit only if not required.'], 'stat <path>; dpkg -S <path>', 'chmod u-s,g-s <path>'),
  temp_executable: R('Investigate executable in temporary directory', ['Identify creator and running processes.', 'Preserve a copy and hash for analysis before removal.'],
    'ls -la <path>; sha256sum <path>', 'Remove only after analysis'),
  suspicious_connection: R('Investigate suspicious network connection', ['Identify the owning process and its binary.', 'Check the destination against threat intelligence.'],
    'ss -tnp; ls -l /proc/<pid>/exe', 'Block via firewall only after confirmation'),
  kernel_param: R('Harden kernel parameter', ['Add the setting to /etc/sysctl.d/99-sentinel.conf.', 'Apply with "sysctl --system" after review.'],
    'sysctl <param>', 'sysctl -w <param>=<value>'),
  disk_usage: R('Free disk space', ['Find large directories (du -xh / | sort -h | tail).', 'Rotate/clean logs, remove unused packages.'], 'df -h', null),
  auditd_inactive: R('Enable auditing', ['Install auditd and enable the service.', 'Load a baseline ruleset.'], 'systemctl is-active auditd', 'apt install auditd && systemctl enable --now auditd'),
  security_update_pending: R('Apply pending security updates', ['Refresh package lists.', 'Apply updates in a maintenance window.'], 'apt list --upgradable', 'apt update && apt upgrade'),
};

export function recommendationFor(finding) {
  const rule = RULES[finding.type] || RULES[finding.type?.replace(/^world_writable_.*/, 'world_writable')];
  if (rule) return rule;
  return R(finding.title, [finding.recommendation || 'Review this finding.'],
    finding.verification?.command || '', finding.requiresAdminApproval ? 'See finding recommendation' : null);
}
