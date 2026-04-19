import subprocess
import threading
import json
import datetime
from pathlib import Path


"""
This is the intrusion prevention system portion of the program. 
It uses iptables to block IPs after an alert gets triggered
"""


BLOCKED_FILE = Path("blocked.log")
_DEFAULT_DURATION = 300.0


# IPS blocking class that blocks and unblocks IPs
class IPSBlocking:
    def __init__(self, whitelist=None, duration=_DEFAULT_DURATION):
        self._lock = threading.Lock()
        self._blocked = {}
        self._whitelist = set(whitelist or [])
        self.duration = duration

    def add_whitelist(self, ip):
        self._whitelist.add(ip)

    def is_blocked(self, ip):
        with self._lock:
            return ip in self._blocked

    def block_ip(self, ip, duration=None):
        if not ip or ip in self._whitelist:
            return
        with self._lock:
            if ip in self._blocked:
                return
            self._blocked[ip] = True
        _iptables_block(ip)
        _log_block(ip, "block")
        t = threading.Timer(duration or self.duration, self._expire, args=[ip])
        t.daemon = True
        t.start()

    def unblock_ip(self, ip):
        with self._lock:
            if ip not in self._blocked:
                return
            self._blocked.pop(ip, None)
        _iptables_unblock(ip)
        _log_block(ip, "unblock")


    def _expire(self, ip):
        self.unblock_ip(ip)

    def blocked_ips(self):
        with self._lock:
            return list(self._blocked.keys())


# blocks the IP using iptables
def _iptables_block(ip):
    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
    except Exception:
        print("failed to block")


# Unblocks the given IP address using iptables
def _iptables_unblock(ip):
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
    except Exception:
        print("failed to unblock")

# Logs the block
def _log_block(ip, action):
    timestamp = datetime.datetime.now().isoformat(timespec="seconds")

    try:
        with BLOCKED_FILE.open("a") as f:
            f.write(json.dumps({"timestamp": timestamp, "ip": ip, "action": action}) + "\n")
    except Exception:
        pass


