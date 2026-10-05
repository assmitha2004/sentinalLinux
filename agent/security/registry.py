"""Check registry and scan-type definitions (spec §56, §86)."""
from .audit import AuditCheck
from .authentication import AuthenticationCheck
from .binaries import BinaryCheck
from .c2 import C2Check
from .cis import CISCheck
from .firewall import FirewallCheck
from .kernel import KernelParamsCheck
from .mac import MACCheck
from .permissions import PermissionsCheck
from .rootkit import RootkitCheck
from .ssh import SSHCheck
from .suid import SUIDCheck
from .tempfiles import TempExecCheck
from .vulnerabilities import VulnerabilityCheck

CHECKS = {c.name: c for c in (SSHCheck(), AuthenticationCheck(), SUIDCheck(), PermissionsCheck(), TempExecCheck(),
                              BinaryCheck(), FirewallCheck(), AuditCheck(), KernelParamsCheck(), MACCheck(),
                              RootkitCheck(), C2Check(), CISCheck(), VulnerabilityCheck())}

# Collectors (system health) are referenced by name with a "collector:" prefix.
QUICK = ["collector:system", "collector:cpu", "collector:memory", "collector:disk", "collector:network",
         "firewall", "kernel_params", "mac", "c2_heuristics"]
STANDARD = QUICK + ["collector:processes", "collector:services", "ssh", "authentication", "permissions",
                    "temp_executables", "audit_logging"]
SCAN_TYPES = {
    "QUICK": QUICK,
    "STANDARD": STANDARD,
    "FULL": STANDARD + ["collector:packages", "suid", "binaries", "rootkit", "vulnerabilities", "benchmark"],
    "BENCHMARK": ["benchmark"],
    "NETWORK": ["collector:network", "firewall", "c2_heuristics", "ssh"],
    "PROCESS": ["collector:processes", "temp_executables", "rootkit"],
    "FILESYSTEM": ["suid", "permissions", "temp_executables", "binaries"],
}
