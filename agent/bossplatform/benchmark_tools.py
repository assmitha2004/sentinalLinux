"""SCAP benchmark discovery (spec §21). We never assume a path: we search known content
directories for datastreams and pick the best match for this OS. No content -> NOT_SUPPORTED."""
import glob
import os

from .capabilities import SCAP_CONTENT_DIRS


def find_datastreams(extra_dirs=()):
    found = []
    for d in (*extra_dirs, *SCAP_CONTENT_DIRS):
        if os.path.isdir(d):
            found += glob.glob(os.path.join(d, "**", "*-ds.xml"), recursive=True)
            found += glob.glob(os.path.join(d, "**", "*-ds-1.2.xml"), recursive=True)
    return sorted(set(found))


def pick_datastream(datastreams, os_info):
    """Prefer content naming this distro (boss), then debian of matching major version, then debian."""
    ids = [os_info.get("id", "").lower(), "boss"]
    deb_major = (os_info.get("debianVersion") or "").split(".")[0]
    prefs = [*ids, f"debian{deb_major}" if deb_major else None, "debian"]
    for p in filter(None, prefs):
        for ds in datastreams:
            if p in os.path.basename(ds).lower():
                return ds
    return None
