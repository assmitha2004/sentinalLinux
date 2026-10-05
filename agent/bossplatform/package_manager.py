"""Package inventory abstraction: dpkg (expected on Debian-based BOSS) or rpm, detected at runtime."""
from util import run

from .capabilities import package_manager_name


def list_packages(reg, limit=20000):
    pm = package_manager_name(reg)
    if pm == "dpkg":
        r = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"], timeout=60)
        if not r:
            return pm, None, r.reason
        pkgs = []
        for line in r.stdout.splitlines()[:limit]:
            parts = line.split("\t")
            if len(parts) >= 4:
                pkgs.append({"name": parts[0], "version": parts[1], "arch": parts[2], "status": parts[3].strip()})
        return pm, pkgs, None
    if pm == "rpm":
        r = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"], timeout=60)
        if not r:
            return pm, None, r.reason
        pkgs = [dict(zip(("name", "version", "arch"), l.split("\t")), status="ii")
                for l in r.stdout.splitlines()[:limit] if l.count("\t") == 2]
        return pm, pkgs, None
    return None, None, "no supported package manager (dpkg/rpm) found"


def _alt_paths(path):
    """On merged-/usr systems (Debian 12 base) dpkg may record /bin/x while the file is at /usr/bin/x."""
    out = [path]
    for a, b in (("/usr/bin/", "/bin/"), ("/usr/sbin/", "/sbin/"), ("/usr/lib/", "/lib/")):
        if path.startswith(a):
            out.append(b + path[len(a):])
        elif path.startswith(b):
            out.append(a + path[len(b):])
    return out


def owner_of(reg, path):
    """Return owning package name for a file, or None."""
    for p in _alt_paths(path):
        owner = _owner_exact(reg, p)
        if owner:
            return owner
    return None


def _owner_exact(reg, path):
    pm = package_manager_name(reg)
    if pm == "dpkg":
        r = run(["dpkg-query", "-S", path], timeout=10)
        if r and ":" in r.stdout:
            return r.stdout.split(":", 1)[0].split(",")[0].strip()
    elif pm == "rpm":
        r = run(["rpm", "-qf", path], timeout=10)
        if r:
            return r.stdout.strip()
    return None


def is_installed(reg, name):
    pm = package_manager_name(reg)
    if pm == "dpkg":
        r = run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}", name], timeout=10)
        return bool(r) and r.stdout.startswith("ii")
    if pm == "rpm":
        return bool(run(["rpm", "-q", name], timeout=10))
    return None
