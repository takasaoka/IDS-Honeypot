import time
import math
from abc import ABC, abstractmethod

"""
This is for SYN flood, UDP flood, ICMP flood detection for DDoS attacks, as well as rate flood detection single source attacks.
It is based off a 3 phase detection method as they all use the same base detection method
"""


# ewma mean
def ewma(x_prev_mean: float, x_n: float, alpha: float):
    return x_prev_mean + alpha * (x_n - x_prev_mean)


# standard deviation
def ewmstd(s_prev: float, x_n: float, x_prev_mean: float, alpha: float):
    return math.sqrt(alpha * (x_n - x_prev_mean) ** 2 + (1.0 - alpha) * s_prev ** 2)


# Threshold, mean + constant k * std deviation
def syn_threshold(mean: float, std: float, k: float):
    return mean + k * std


# Single packet ratio
def single_packet_ratio(c_single: int, c_total: int):
    if c_total == 0:
        return 0.0
    return (c_single / c_total) * 100.0



# Single packet ratio threshold - mean + std deviation
def pr_threshold(pr_mean: float, pr_std: float):
    return pr_mean + pr_std



# Permanent IP address database
class PAD:
    def __init__(self, ttl: float = 30.0):
        self._store: dict[str, float] = {}
        self.ttl = ttl


    def add(self, ip: str):
        self._store[ip] = time.time()


    def add_all(self, ips):
        now = time.time()
        for ip in ips:
            self._store[ip] = now


    def contains(self, ip: str):
        return ip in self._store

    def __len__(self):
        return len(self._store)

    def expire(self):
        cutoff = time.time() - self.ttl
        
        expired = [ip for ip, ts in self._store.items() if ts < cutoff]
        print("expired", expired)
        for ip in expired:
            self._store.pop(ip, None)



# Base abstract flood detector class for DDoS attacks
class FloodDetector(ABC):
    def __init__(
        self,
        window_sec: float = 3.0,
        alpha: float = 0.5,
        k: float = 1.0,
        pad_ttl: float = 30.0,
        consecutive_required: int = 3,
    ):
        self.window_sec = window_sec
        self.alpha = alpha
        self.k = k
        self.consecutive_required = consecutive_required
        self.pad = PAD(ttl=pad_ttl)
        self._pkt_count: int = 0
        self._pkt_mean: float = 0.0
        self._pkt_std: float = 1.0
        self._pkt_threshold: float = 0.0
        self._windows_seen: int = 0
        self._pr_mean: float = 0.0
        self._pr_std: float = 1.0
        self._pr_threshold: float = 0.0
        self._consecutive_high_pr: int = 0
        self._flow_packets: dict[tuple, int] = {}
        self._tad: set[str] = set()
        self._window_start: float = time.time()
        self.attack_active: bool = False
        self.phase1_warning: bool = False
        self.attacking_ips: list = []



    @abstractmethod
    def _match(self, obj: dict):
        pass


    @abstractmethod
    def _correct_packet(self, obj: dict):
        pass


    def _flow_key(self, obj: dict):
        return (obj.get("src_ip", ""), obj.get("dst_ip", ""), obj.get("src_port", 0), obj.get("dst_port", 0))

    def process(self, obj: dict):
        if not self._match(obj):
            return False
        

        now = time.time()

        if now - self._window_start >= self.window_sec:
            result = self._end_window(now)
            src_ip = obj.get("src_ip", "")
            if self._correct_packet(obj):
                self._pkt_count += 1
                self._tad.add(src_ip)
            flow = self._flow_key(obj)
            self._flow_packets[flow] = self._flow_packets.get(flow, 0) + 1
            return result


        src_ip = obj.get("src_ip", "")

        if self._correct_packet(obj):
            self._pkt_count += 1
            self._tad.add(src_ip)

        
        flow = self._flow_key(obj)
        self._flow_packets[flow] = self._flow_packets.get(flow, 0) + 1

        return False



    # processes everything and checks for triggers
    def _end_window(self, now: float):
        confirmed = False
        x_n = float(self._pkt_count)

        prev_mean = self._pkt_mean
        self._pkt_mean = ewma(self._pkt_mean, x_n, self.alpha)
        self._pkt_std = ewmstd(self._pkt_std, x_n, prev_mean, self.alpha)
        delta = syn_threshold(self._pkt_mean, self._pkt_std, self.k)
        phase1_triggered = (self._windows_seen > 0) and (x_n > self._pkt_threshold)

        self._windows_seen += 1

        if not phase1_triggered:
            self.pad.add_all(self._tad)
            self.pad.expire()
            self._pkt_threshold = delta
            self.phase1_warning = False


            pr_n = self._calculate_pr()
            prev_pr_mean = self._pr_mean
            self._pr_mean = ewma(self._pr_mean, pr_n, self.alpha)
            self._pr_std  = ewmstd(self._pr_std, pr_n, prev_pr_mean, self.alpha)
            self._pr_threshold = pr_threshold(self._pr_mean, self._pr_std)
            self._consecutive_high_pr = 0
        else:
            self.phase1_warning = True

            single_flows = self._single_packet_flows()
            unknown_ips = [flow[0] for flow in single_flows if not self.pad.contains(flow[0])]

            if not unknown_ips:
                self.phase1_warning = False
                self.pad.add_all(self._tad)
                self.pad.expire()
                self._pkt_threshold = delta
                self._consecutive_high_pr = 0
            else:
                pr_n = self._calculate_pr()
                prev_pr_mean = self._pr_mean
                self._pr_mean = ewma(self._pr_mean, pr_n, self.alpha)
                self._pr_std  = ewmstd(self._pr_std, pr_n, prev_pr_mean, self.alpha)

                if pr_n > self._pr_threshold:
                    self._consecutive_high_pr += 1
                else:
                    self._consecutive_high_pr = 0


                if self._consecutive_high_pr >= self.consecutive_required:
                    self.attack_active = True
                    self.attacking_ips = list(unknown_ips)
                    confirmed = True

        self._pkt_count = 0
        self._flow_packets.clear()
        self._tad.clear()
        self._window_start = now

        return confirmed


    # Gets single packet flows
    def _single_packet_flows(self):
        return [flow for flow, cnt in self._flow_packets.items() if cnt == 1]


    # Calculates percentage ratio
    def _calculate_pr(self):
        c_single = len(self._single_packet_flows())
        c_total = len(self._flow_packets)
        return single_packet_ratio(c_single, c_total)

    # Resets attack
    def reset_attack(self):
        self.attack_active = False
        self.phase1_warning = False
        self._consecutive_high_pr = 0
        self.attacking_ips = []



# Inherits from flood detector for syn flood detection
class SynFloodDetector(FloodDetector):
    def _match(self, obj: dict):
        return obj.get("proto") == "tcp"
    

    def _correct_packet(self, obj: dict):
        flags = obj.get("tcp_flags", [])
        return isinstance(flags, list) and "SYN" in flags and "ACK" not in flags



# UDP flood detection
class UdpFloodDetector(FloodDetector):
    def _match(self, obj: dict):
        return obj.get("proto") == "udp"
    

    def _correct_packet(self, obj: dict):
        return True



# ICMP flood detection
class IcmpFloodDetector(FloodDetector):
    def _match(self, obj: dict):
        return obj.get("proto") == "icmp"
    

    def _correct_packet(self, obj: dict):
        return obj.get("icmp_type") == 8

    def _flow_key(self, obj: dict):
        return (
            obj.get("src_ip", ""),
            obj.get("dst_ip", ""),
            obj.get("icmp_type", 0),
            obj.get("icmp_code", 0),
        )


# Uses the HTTP flood detection method
class RateFloodDetector:
    def __init__(
        self,
        window_sec: float = 3.0,
        alpha: float = 0.5,
        a: float = 0.1,
        consecutive_required: int = 3,
        local_ip=None,
    ):
        self.window_sec = window_sec
        self.alpha = alpha
        self.a = a
        self.consecutive_required = consecutive_required
        self.local_ip = local_ip

        self._total_mean: float = 0.0
        self._total_std: float = 1.0
        self._total_threshold: float = 0.0
        self._windows_seen: int = 0

        self._host_bytes: dict[str, int] = {}
        self._total_bytes: int = 0
        self._host_consecutive: dict[str, int] = {}

        self._window_start: float = time.time()
        self.attack_active: bool = False
        self.phase1_warning: bool = False
        self.attacking_ips: list = []
    

    def process(self, obj: dict):
        if not isinstance(obj, dict):
            return False

        if self.local_ip and obj.get("src_ip") == self.local_ip:
            return False

        now = time.time()

        if now - self._window_start >= self.window_sec:
            return self._end_window(now)

        src_ip = obj.get("src_ip", "")
        length = obj.get("len", 0)

        self._total_bytes += length
        self._host_bytes[src_ip] = self._host_bytes.get(src_ip, 0) +length

        return False
    
    
    def _avg_legitimate_rate(self, attacking_ips: set):
        legitimate = {ip: b for ip, b in self._host_bytes.items() if ip not in attacking_ips}
        if not legitimate:
            return 0.0
        return sum(legitimate.values()) / float(len(legitimate))

    def _calculate_m(self, t_n: float, n: int, r_bar: float):
        if n == 0 or r_bar == 0.0:
            return 0.0
        return max(0.0, (t_n / (self.a * n * r_bar)) - (1.0 / self.a - 1.0 - 1.0))



    def _end_window(self, now: float):
        confirmed = False
        t_n = float(self._total_bytes)
        n = len(self._host_bytes)
        prev_mean = self._total_mean
        self._total_mean = ewma(self._total_mean, t_n, self.alpha)
        self._total_std = ewmstd(self._total_std, t_n, prev_mean, self.alpha)
        delta = syn_threshold(self._total_mean, self._total_std * 3.0, 1.0)
        phase1_triggered = (self._windows_seen > 0) and (t_n > self._total_threshold)


        self._windows_seen += 1

        if not phase1_triggered:
            self._total_threshold = delta
            self.phase1_warning = False
            for ip in list(self._host_consecutive.keys()):
                self._host_consecutive[ip] = 0
        else:
            self.phase1_warning = True

            r_bar = self._avg_legitimate_rate(set())
            m = self._calculate_m(t_n, n, r_bar)
            threshold = m * r_bar


            if threshold > 0.0:
                new = []
                for ip, host_bytes in self._host_bytes.items():
                    if host_bytes > threshold:
                        self._host_consecutive[ip] = self._host_consecutive.get(ip, 0) + 1
                        if self._host_consecutive[ip] >= self.consecutive_required:
                            new.append(ip)
                    else:
                        self._host_consecutive[ip] = 0

                if new:
                    self.attack_active = True
                    self.attacking_ips = new
                    confirmed = True
            else:
                self.phase1_warning = False

        self._host_bytes.clear()
        self._total_bytes = 0
        self._window_start = now

        return confirmed


    # Resets attack
    def reset_attack(self):
        self.attack_active = False
        self.phase1_warning = False
        self.attacking_ips = []
        self._host_consecutive.clear()



# XMAS scan detection - just checks fin psh urg flags in tcp packet
class XmasScanDetector:
    def __init__(self):
        self.triggered = False
        

    def process(self, obj):
        if obj.get("proto") != "tcp":
            return False
        flags = obj.get("tcp_flags", [])
        if "FIN" in flags and "PSH" in flags and "URG" in flags:
            self.triggered = True
            return True
        return False


    def reset_attack(self):
        self.triggered = False




