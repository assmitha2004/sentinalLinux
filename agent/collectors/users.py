"""Local user inventory (spec §15). Reads /etc/passwd only; password hashes are never collected."""
import os
import pwd

from util import result

NOLOGIN = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "/bin/sync")


def list_users():
    users = []
    for u in pwd.getpwall():
        users.append({"name": u.pw_name, "uid": u.pw_uid, "gid": u.pw_gid, "home": u.pw_dir, "shell": u.pw_shell,
                      "canLogin": u.pw_shell not in NOLOGIN and bool(u.pw_shell),
                      "homeExists": os.path.isdir(u.pw_dir)})
    return users


def collect(ctx):
    users = list_users()
    return result("users", "PASS", {"users": users, "count": len(users),
                                    "loginCapable": sum(u["canLogin"] for u in users)})
