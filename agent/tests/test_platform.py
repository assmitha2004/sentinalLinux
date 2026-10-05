from bossplatform.benchmark_tools import pick_datastream
from bossplatform.capabilities import CapabilityRegistry
from bossplatform.os_detection import detect_os, parse_os_release
from bossplatform.package_manager import _alt_paths

BOSS10 = '''PRETTY_NAME="BOSS GNU/Linux 10 (unnati)"
NAME="BOSS GNU/Linux"
VERSION_ID="10"
VERSION="10 (unnati)"
VERSION_CODENAME=unnati
ID=boss
ID_LIKE=debian
'''


def test_parse_os_release_quotes_and_comments():
    d = parse_os_release('# c\nNAME="X Y"\nID=x\n\nBAD LINE\n')
    assert d == {"NAME": "X Y", "ID": "x"}


def test_detect_boss10():
    o = detect_os(BOSS10)
    assert o["distribution"] == "BOSS" and o["version"] == "10" and o["isBoss10"]
    assert o["codename"] == "unnati"
    assert o["kernel"] and o["architecture"] and o["hostname"]


def test_detect_non_boss_is_not_misreported():
    o = detect_os('NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n')
    assert not o["isBoss"] and not o["isBoss10"] and o["distribution"] == "Ubuntu"


def test_detect_other_boss_version():
    o = detect_os('NAME="BOSS GNU/Linux"\nID=boss\nVERSION_ID="9"\n')
    assert o["isBoss"] and not o["isBoss10"]


def test_capability_registry_reports_missing_commands():
    reg = CapabilityRegistry(commands=("sh", "definitely-not-a-real-cmd-xyz", "ip", "ss", "netstat", "journalctl",
                                       "auditctl", "oscap", "rkhunter", "chkrootkit", "nft", "iptables",
                                       "firewall-cmd", "sshd", "systemctl", "dpkg-query", "rpm"))
    assert reg.has("sh") is True
    assert reg.has("definitely-not-a-real-cmd-xyz") is False
    s = reg.summary({"initSystem": "systemd"})
    assert isinstance(s["isRoot"], bool) and "openscap" in s


def test_merged_usr_alt_paths():
    assert "/bin/su" in _alt_paths("/usr/bin/su")
    assert "/usr/sbin/x" in _alt_paths("/sbin/x")


def test_pick_datastream_prefers_boss_then_debian():
    ds = ["/a/ssg-debian11-ds.xml", "/a/ssg-debian12-ds.xml", "/a/ssg-boss10-ds.xml"]
    assert pick_datastream(ds, {"id": "boss", "debianVersion": "12.5"}).endswith("boss10-ds.xml")
    assert pick_datastream(ds[:2], {"id": "boss", "debianVersion": "12.5"}).endswith("debian12-ds.xml")
    assert pick_datastream(["/a/ssg-rhel9-ds.xml"], {"id": "boss", "debianVersion": "12"}) is None
