"""Binary inventory (spec §19). Hashes only on request (paths.hash_binaries) or for anomalies."""
import os
import pwd
import stat
import time

from bossplatform import package_manager as pm
from models.schemas import finding
from util import result, status_from_findings

from .base import SecurityCheck
from .suid import sha256

MAX_INVENTORY = 5000


class BinaryCheck(SecurityCheck):
    name, category, slow = "binaries", "filesystem", True

    def run(self, ctx):
        dirs = [d for d in ctx.cfg["paths"]["binaries"] if os.path.isdir(d) and not os.path.islink(d)]
        hash_all = ctx.cfg["paths"]["hash_binaries"]
        inv, findings, now = [], [], time.time()
        for d in dirs:
            dst = os.stat(d)
            if dst.st_mode & stat.S_IWOTH:
                findings.append(finding("binary_dir_world_writable", "filesystem", "CRITICAL",
                                        f"System binary directory {d} is world-writable",
                                        f"{d} mode {oct(dst.st_mode & 0o777)}.", {"path": d},
                                        "Restore 755 root:root permissions after investigation.",
                                        f"stat {d}", confidence=0.95, resource=d, requires_approval=True))
            try:
                names = sorted(os.listdir(d))
            except OSError:
                continue
            for n in names:
                p = os.path.join(d, n)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                item = {"path": p, "size": st.st_size, "mode": stat.filemode(st.st_mode), "uid": st.st_uid,
                        "mtime": int(st.st_mtime)}
                if hash_all:
                    item["sha256"] = sha256(p)
                if st.st_uid != 0 and not d.startswith("/usr/local"):
                    item["package"] = pm.owner_of(ctx.reg, p)
                    item["sha256"] = item.get("sha256") or sha256(p)
                    try:
                        owner = pwd.getpwuid(st.st_uid).pw_name
                    except KeyError:
                        owner = str(st.st_uid)
                    findings.append(finding("binary_non_root_owner", "filesystem", "MEDIUM",
                                            f"System binary not owned by root: {p}",
                                            f"{p} is owned by '{owner}'; that user can replace a system command.",
                                            item, "Verify package ownership; restore root ownership if appropriate.",
                                            f"ls -l {p}; dpkg -S {p}", confidence=0.7, resource=p,
                                            requires_approval=True))
                if st.st_mode & stat.S_IWOTH:
                    findings.append(finding("binary_world_writable", "filesystem", "CRITICAL",
                                            f"World-writable system binary: {p}", f"{p} can be modified by any user.",
                                            item, "chmod o-w after investigation.", f"ls -l {p}", confidence=0.95,
                                            resource=p, requires_approval=True))
                if len(inv) < MAX_INVENTORY:
                    inv.append(item)
        recent = [i for i in inv if now - i["mtime"] < 7 * 86400]
        data = {"directories": dirs, "count": len(inv), "recentlyModified": recent[:200],
                "inventory": inv, "truncated": len(inv) >= MAX_INVENTORY}
        return result(self.name, status_from_findings(findings), data, findings)
