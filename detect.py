import time, datetime, os, argparse
from pathlib import Path
from collections import deque
import numpy as np
from sklearn.ensemble import IsolationForest
import subprocess
import sys
import os
import json
import math
from scipy.stats import entropy
from collections import Counter
import socket
import threading
from signaturedetect import (SynFloodDetector, UdpFloodDetector, IcmpFloodDetector, RateFloodDetector)
from ips import IPSBlocking

"""
This file has a combination of signature based detection and anomaly based detection.
The signature detection has a single detection method for DoS attacks currently for a certain amount of requests within a timeframe
Anomaly based detction using isolation forest, mainly just setup for testing purposes before I build upon it. 
"""

WINDOW = 10
THRESHOLD = 10000000
ALERTS_FILE = Path("alerts.log")
LLM_ALERTS_FILE = Path("llm_alerts.log")



#Logs alert
def log_alert(alert_type, message):
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    try:
        with ALERTS_FILE.open("a") as f:
            f.write(json.dumps({"timestamp": ts, "type": alert_type, "message": message}) + "\n")
    except Exception:
        pass


# Logs llm response
def log_llm(alert_type, obj):
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    try:
        with LLM_ALERTS_FILE.open("a") as f:
            f.write(json.dumps({"timestamp": ts, "type": alert_type, "llm": obj}) + "\n")
    except Exception:
        pass


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
        
    return buf


# Queries the llm running on other machine
def call_llm_tcp(alert, host, port, model, timeout):
    req = json.dumps({"alert": alert, "model": model, "timeout": timeout}).encode("utf-8")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(len(req).to_bytes(4, "big") + req)
        header = recv_exact(s, 4)
        if not header:
            return None
        length = int.from_bytes(header, "big")
        payload = recv_exact(s, length)
        if payload is None:
            return None
        return json.loads(payload.decode("utf-8", errors="ignore"))
    
    finally:
        try:
            s.close()
        except Exception:
            pass



# Message format for llm
def baseline_llm_message(lines, now_iso):
    samples = []
    for line in lines:
        if line is None:
            continue
        s = str(line)
        samples.append(s[:200])

    return {
        "timestamp": now_iso,
        "source": "baseline",
        "event_count": len(lines),
        "samples": samples[:10]
    }


# Message format for llm
def honeypot_llm_message(objs, now_iso):
    samples = []
    ips = []
    ports = []
    for obj in objs:
        if not isinstance(obj, dict):
            continue
        data = obj.get("data", "")
        ip = obj.get("remote_ip", "")
        port = obj.get("port", 0)
        ips.append(ip)
        ports.append(port)
        s = str(data)
        samples.append(s[:200])

    top_ips = Counter(ips).most_common(5) if ips else []
    top_ports = Counter(ports).most_common(5) if ports else []

    return {
        "timestamp": now_iso,
        "source": "honeypot",
        "event_count": len(objs),
        "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        "top_ports": [{"port": p, "count": c} for p, c in top_ports],
        "samples": samples[:10]
    }



# Prepares data for llm in specific format
def network_llm_message(objs, now_iso):
    samples = []
    srcs = []
    dst_ports = []
    protos = []
    flags = []
    for obj in objs:
        if not isinstance(obj, dict):
            continue
        prot = obj.get("proto", "")
        protos.append(prot)
        srcs.append(obj.get("src_ip", ""))
        dp = obj.get("dst_port", None)
        if dp is not None:
            dst_ports.append(dp)
        tf = obj.get("tcp_flags", [])
        if isinstance(tf, list) and tf:
            flags.append(",".join(tf))
        samples.append(json.dumps(obj)[:200])

    top_srcs = Counter(srcs).most_common(5) if srcs else []
    top_ports = Counter(dst_ports).most_common(5) if dst_ports else []
    top_protocols = Counter(protos).most_common(5) if protos else []
    top_flags = Counter(flags).most_common(5) if flags else []

    return {
        "timestamp": now_iso,
        "source": "network",
        "event_count": len(objs),
        "top_src_ips": [{"ip": ip, "count": c} for ip, c in top_srcs],
        "top_dst_ports": [{"port": p, "count": c} for p, c in top_ports],
        "top_protocols": [{"proto": p, "count": c} for p, c in top_protocols],
        "top_tcp_flags": [{"flags": f, "count": c} for f, c in top_flags],
        "samples": samples[:10]
    }



def read(path: Path):
    if path.is_file():
        with path.open("r", buffering=1) as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if line:
                    yield line
                else:
                    time.sleep(0.1)
    else:
        current = None
        f = None
        while True:
            latest = None
            try:
                files = [p for p in path.iterdir() if p.is_file()]
                files.sort(key=os.path.getmtime)
                latest = files[-1] if files else None
            except Exception:
                latest = None
            if latest is not None and latest != current:
                if f:
                    try:
                        f.close()
                    except Exception:
                        pass
                current = latest
                try:
                    f = current.open("r", buffering=1)
                    f.seek(0, os.SEEK_END)
                except Exception:
                    f = None
            if f:
                line = f.readline()
                if line:
                    yield line
                else:
                    time.sleep(0.1)
            else:
                time.sleep(0.1)

# Uses shannon entropy, taken from: https://www.geeksforgeeks.org/machine-learning/how-to-compute-entropy-using-scipy/
def _randomness(b):
    if not b:
        return 0.0
    
    counts = Counter(b)
    
    total = float(len(b))
    x = [c/total for c in counts.values()]
    return entropy(x, base=2)


# checks for regular characters
def _printable(s:str):
    if not s:
        return 0.0
    
    count = 0
    for c in s:
        if c.isprintable():
            count += 1
    return float(count) / float(len(s))


def _extract_http_ip(line):
    try:
        ip = line.strip().split()[0]
        socket.inet_aton(ip)
        return ip
    except Exception:
        return None

#features from the baseline for before honeypot activates
def _features_baseline(line, now, prev_timestamp, recent):
    if prev_timestamp is None:
        timestamp = 0.0
    else:
        timestamp = now - prev_timestamp
    b = line.encode(errors="ignore")
    randomness = _randomness(b)
    printable = _printable(line)
    if WINDOW > 0:
        rate = len(recent) / WINDOW
    else:
        rate = 0.0
    port = 8080.0
    line_length = float(len(line))
    return [line_length, float(timestamp), randomness, printable, rate, port]


# Features from the honeypot
def _features_honeypot(obj, now, prev_timestamp, recent):
    timestamp = None
    data = ""
    port = 0.0

    try:
        timestamp2 = obj.get("timestamp")
        if timestamp2:
            timestamp = datetime.datetime.fromisoformat(timestamp2).timestamp()
        data = obj.get("data","")
        p = obj.get("port", 0)
        port = float(p) if p is not None else 0.0
    except Exception:
        pass

    if prev_timestamp is None:
        dt = 0.0
    else:
        if timestamp is not None:
            dt = timestamp - prev_timestamp
        else:
            dt = now - prev_timestamp
    b = data.encode(errors="ignore")
    randomness = _randomness(b)
    printable = _printable(data)
    if WINDOW > 0:
        rate = len(recent) / WINDOW
    else:
        rate = 0.0
    line_length = float(len(data))


    return [line_length, float(dt), randomness, printable, rate, port], timestamp, data


# Gets own ip
def get_own_ip(iface):
    try:
        import fcntl
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), 0x8915,
            struct.pack('256s', iface[:15].encode())
        )[20:24])
    except Exception:
        return None


# Starts network capturing
def start_network_cap(iface, out_path):
    try:
        return subprocess.Popen(
            [sys.executable, "-u", "packetcap.py", "--iface", iface, "--out", out_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return None


# Monitors the network
def network_monitor(out_path, args, stop_event, ips_blocking=None):
    p = Path(out_path)
    recent_net_events = deque(maxlen=400)

    while not stop_event.is_set():
        if not p.exists():
            time.sleep(0.2)
            continue
        break

    syn_detector = SynFloodDetector(window_sec=3.0, alpha=0.5, k=1.0, pad_ttl=30.0, consecutive_required=3)
    udp_detector = UdpFloodDetector(window_sec=3.0, alpha=0.5, k=1.0, pad_ttl=30.0, consecutive_required=3)

    icmp_detector = IcmpFloodDetector(window_sec=3.0, alpha=0.5, k=1.0, pad_ttl=30.0, consecutive_required=3)

    local_ip = get_own_ip(args.net_iface)


    rate_detector = RateFloodDetector( window_sec=3.0, alpha=0.5, a=0.1, consecutive_required=3, local_ip=local_ip)

    try:
        for line in read(p):
            if stop_event.is_set():
                break
            line = line.strip()

            if not line:
                continue

            obj = None
            try:
                obj = json.loads(line)
            except Exception:
                obj = None
            if not isinstance(obj, dict):
                continue

            recent_net_events.append(obj)

            attack_alert = syn_detector.process(obj)



            if attack_alert:
                ts = datetime.datetime.now().isoformat(timespec="seconds")
                pad_size = len(syn_detector.pad)
                msg = (
                    f"SYN flood confirmed — "
                    f"3 consecutive windows, "
                    f"PAD size={pad_size}"
                )
                log_alert("syn_flood", msg)
                Path("honeypot_enabled").touch(exist_ok=True)

                if args.llm:
                    try:
                        now_iso = datetime.datetime.now().isoformat(timespec="seconds")
                        alert = network_llm_message(list(recent_net_events), now_iso)
                        alert["syn_flood_meta"] = {
                            "pkt_mean": round(syn_detector._pkt_mean, 2),
                            "pkt_std": round(syn_detector._pkt_std, 2),
                            "pkt_threshold": round(syn_detector._pkt_threshold, 2),
                            "pr_mean": round(syn_detector._pr_mean, 2),
                            "pr_std": round(syn_detector._pr_std, 2),
                            "pr_threshold": round(syn_detector._pr_threshold, 2),
                            "pad_size": pad_size
                        }
                        llm_obj = call_llm_tcp(
                            alert,
                            args.llm_host,
                            args.llm_port,
                            args.llm_model,
                            args.llm_timeout
                        )
                        if isinstance(llm_obj, dict) and "error" not in llm_obj:
                            log_llm("syn_flood", llm_obj)
                    except Exception:
                        pass

                if ips_blocking:
                    for ip in syn_detector.attacking_ips:
                        ips_blocking.block_ip(ip)
                syn_detector.reset_attack()

            elif syn_detector.phase1_warning:
                ts = datetime.datetime.now().isoformat(timespec="seconds")\
            

            udp_alert = udp_detector.process(obj)

            if udp_alert:
                
                ts = datetime.datetime.now().isoformat(timespec="seconds")
                pad_size = len(udp_detector.pad)
                msg = (
                    f"UDP flood confirmed — "
                    f"3 consecutive windows, "
                    f"PAD size={pad_size}"
                )
                log_alert("udp_flood", msg)
                Path("honeypot_enabled").touch(exist_ok=True)


                if args.llm:
                    try:
                        now_iso = datetime.datetime.now().isoformat(timespec="seconds")
                        alert = network_llm_message(list(recent_net_events), now_iso)
                        alert["udp_flood_meta"] = {
                            "pkt_mean": round(udp_detector._pkt_mean, 2),
                            "pkt_std": round(udp_detector._pkt_std, 2),
                            "pkt_threshold": round(udp_detector._pkt_threshold, 2),
                            "pr_mean": round(udp_detector._pr_mean, 2),
                            "pr_std": round(udp_detector._pr_std, 2),
                            "pr_threshold": round(udp_detector._pr_threshold, 2),
                            "pad_size": pad_size
                        }
                        llm_obj = call_llm_tcp(
                            alert,
                            args.llm_host,
                            args.llm_port,
                            args.llm_model,
                            args.llm_timeout
                        )
                        if isinstance(llm_obj, dict) and "error" not in llm_obj:
                            log_llm("udp_flood", llm_obj)
                    except Exception:
                        pass

                if ips_blocking:
                    for ip in udp_detector.attacking_ips:
                        ips_blocking.block_ip(ip)
                udp_detector.reset_attack()

            elif udp_detector.phase1_warning:
                ts = datetime.datetime.now().isoformat(timespec="seconds")

            icmp_alert = icmp_detector.process(obj)

            if icmp_alert:
                ts = datetime.datetime.now().isoformat(timespec="seconds")
                pad_size = len(icmp_detector.pad)
                msg = (
                    f"ICMP flood confirmed — "
                    f"3 consecutive windows, "
                    f"PAD size={pad_size}"
                )

                log_alert("icmp_flood", msg)
                Path("honeypot_enabled").touch(exist_ok=True)

                if args.llm:
                    try:
                        now_iso = datetime.datetime.now().isoformat(timespec="seconds")
                        alert = network_llm_message(list(recent_net_events), now_iso)
                        alert["icmp_flood_meta"] = {
                            "pkt_mean": round(icmp_detector._pkt_mean, 2),
                            "pkt_std": round(icmp_detector._pkt_std, 2),
                            "pkt_threshold": round(icmp_detector._pkt_threshold, 2),
                            "pr_mean": round(icmp_detector._pr_mean, 2),
                            "pr_std": round(icmp_detector._pr_std, 2),
                            "pr_threshold": round(icmp_detector._pr_threshold, 2),
                            "pad_size": pad_size
                        }
                        llm_obj = call_llm_tcp(
                            alert,
                            args.llm_host,
                            args.llm_port,
                            args.llm_model,
                            args.llm_timeout
                        )
                        if isinstance(llm_obj, dict) and "error" not in llm_obj:
                            log_llm("icmp_flood", llm_obj)
                    except Exception:
                        pass

                if ips_blocking:
                    for ip in icmp_detector.attacking_ips:
                        ips_blocking.block_ip(ip)
                icmp_detector.reset_attack()

            elif icmp_detector.phase1_warning:
                ts = datetime.datetime.now().isoformat(timespec="seconds")
            rate_alert = rate_detector.process(obj)


            if rate_alert:
                ts = datetime.datetime.now().isoformat(timespec="seconds")
                ips = rate_detector.attacking_ips
                msg = (
                    f"rate flood confirmed — "
                    f"attacking IPs: {ips}"
                )
                log_alert("rate_flood", msg)
                Path("honeypot_enabled").touch(exist_ok=True)

                if args.llm:
                    try:
                        now_iso = datetime.datetime.now().isoformat(timespec="seconds")


                        alert = network_llm_message(list(recent_net_events), now_iso)
                        alert["rate_flood_meta"] = {
                            "total_mean": round(rate_detector._total_mean, 2),
                            "total_std": round(rate_detector._total_std, 2),
                            "total_threshold": round(rate_detector._total_threshold, 2),
                            "attacking_ips": ips
                        }

                        llm_obj = call_llm_tcp(
                            alert,
                            args.llm_host,
                            args.llm_port,
                            args.llm_model,
                            args.llm_timeout
                        )
                        if isinstance(llm_obj, dict) and "error" not in llm_obj:
                            log_llm("rate_flood", llm_obj)
                    except Exception:
                        pass

                if ips_blocking:
                    for ip in rate_detector.attacking_ips:
                        ips_blocking.block_ip(ip)
                rate_detector.reset_attack()

            elif rate_detector.phase1_warning:
                ts = datetime.datetime.now().isoformat(timespec="seconds")


    except Exception:
        pass


# Main function
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--isoforest", action="store_true")
    ap.add_argument("--baseline", type=int, default=5)
    ap.add_argument("--contamination", type=float, default=0.3)
    ap.add_argument("--llm", action="store_true")
    ap.add_argument("--llm-host", type=str, default=os.getenv("LLM_HOST","127.0.0.1"))
    ap.add_argument("--llm-port", type=int, default=int(os.getenv("LLM_PORT","5555")))
    ap.add_argument("--llm-model", type=str, default=os.getenv("LLM_MODEL","llama3.1:8b"))
    ap.add_argument("--llm-timeout", type=int, default=int(os.getenv("LLM_TIMEOUT","60")))
    ap.add_argument("--net", action="store_true")
    ap.add_argument("--net-iface", type=str, default=os.getenv("NET_IFACE","enp0s3"))
    ap.add_argument("--net-out", type=str, default=os.getenv("NET_OUT","network_logs.log"))
    ap.add_argument("--ips", action="store_true")
    ap.add_argument("--ips-duration", type=int, default=300)
    ap.add_argument("--ips-whitelist", type=str, default="")
    args = ap.parse_args()

    logs_dir = Path("honeypot_logs")
    logs_dir.mkdir(exist_ok=True)
    print(f"dir: {logs_dir} window:{WINDOW}s threshold: {THRESHOLD}")

    ips_blocking = IPSBlocking(duration=args.ips_duration) if args.ips else None
    if ips_blocking:
        local_ip = get_own_ip(args.net_iface)
        if local_ip:
            ips_blocking.add_whitelist(local_ip)
        if args.ips_whitelist:
            for _wip in args.ips_whitelist.split(","):
                _wip = _wip.strip()
                if _wip:
                    ips_blocking.add_whitelist(_wip)

    recent = deque()
    model = None
    baseline = []
    trained = False
    prev_timestamp = None
    logs_dir = Path("honeypot_logs")
    logs_dir.mkdir(exist_ok=True)
    
    active_log = Path(os.path.join(str(logs_dir), f"active_{datetime.datetime.now().strftime('%Y%m%d')}.log"))
    http_log = Path(os.path.join(str(logs_dir), "http.log"))
    http_log_handle = None
    server_proc = None

    honeypot_source = False

    baseline_dir = Path("baseline_logs")
    baseline_dir.mkdir(exist_ok=True)
    baseline_active_log = baseline_dir / f"baseline_{datetime.datetime.now().strftime('%Y%m%d')}.log"

    recent_baseline_events = deque(maxlen=200)
    recent_honeypot_events = deque(maxlen=200)

    net_proc = None
    net_stop = threading.Event()
    net_thread = None
    if args.net:
        net_proc = start_network_cap(args.net_iface, args.net_out)
        net_thread = threading.Thread(target=network_monitor, args=(args.net_out, args, net_stop, ips_blocking))
        net_thread.daemon = True

        net_thread.start()

    if args.isoforest:
        try:
            files = [p for p in baseline_dir.iterdir() if p.is_file() and p.name.startswith("baseline_")]
            files.sort(key=os.path.getmtime)
            previous = None
            prev = None
            for previous in files:
                try:
                    with previous.open("r", buffering=1) as f:
                        for line in f:
                            features = _features_baseline(line, 0.0, prev, [])
                            prev = 0.0 if prev is None else prev
                            baseline.append(features)
                except Exception:
                    pass
            if len(baseline) >= max(1, args.baseline):
                x_train = np.array(baseline, dtype=float)
                model = IsolationForest(contamination=args.contamination, random_state=42)
                model.fit(x_train)
                trained = True
        except Exception:
            pass

    http_log_handle = http_log.open("a", buffering=1)
    server_proc = subprocess.Popen(
        [sys.executable, "-u", "-m", "http.server", "8080", "--bind", "0.0.0.0"],
        stdout=http_log_handle,
        stderr=subprocess.STDOUT
    )
    log_lines2elixir = read(http_log)

    triggered = False

    try:
        for line in log_lines2elixir:
            with baseline_active_log.open("a") as baf:
                baf.write(line)
            recent_baseline_events.append(line)
            # Signature detection based on specific amount within specified time frame based on the window and threshold above
            now = time.time()
            recent.append(now)
            cutoff = now - WINDOW
            while recent and recent[0] < cutoff:
                # print("recent:", recent[0]) # check again later
                recent.popleft()

            signature_triggered = False
            if len(recent) >= THRESHOLD:
                ts = datetime.datetime.now().isoformat(timespec="seconds")
                print(f"timestamp: {ts} {len(recent)} events in last {WINDOW} seconds")
                Path("honeypot_enabled").touch(exist_ok=True)
                log_alert("baseline_dos", f"{len(recent)} events in last {WINDOW} seconds")
                if ips_blocking:
                    seen = set()
                    for bl in recent_baseline_events:
                        ip = _extract_http_ip(str(bl))
                        if ip and ip not in seen:
                            ips_blocking.block_ip(ip)
                            seen.add(ip)
                if args.llm:
                    try:
                        now_iso = datetime.datetime.now().isoformat(timespec="seconds")
                        alert = baseline_llm_message(list(recent_baseline_events), now_iso)
                        obj = call_llm_tcp(alert, args.llm_host, args.llm_port, args.llm_model, args.llm_timeout)
                        if isinstance(obj, dict) and "error" not in obj:
                            log_llm("baseline_dos", obj)
                    except Exception:
                        pass
                signature_triggered = True

            # For anomaly detection
            if args.isoforest:
                features = _features_baseline(line, now, prev_timestamp, recent)
                prev_timestamp = now
                if not trained:
                    baseline.append(features)
                    if len(baseline) >= args.baseline:
                        x_train = np.array(baseline, dtype=float)
                        model = IsolationForest(contamination=args.contamination, random_state=42)
                        model.fit(x_train)
                        trained = True
                else:
                    x_test = np.array(features, dtype=float).reshape(1, -1)
                    predict = model.predict(x_test)[0]
                    if predict == -1:
                        ts = datetime.datetime.now().isoformat(timespec="seconds")
                        print(f"timestamp: {ts} anomaly detected len={int(features[0])} dt={features[1]:.3f}")
                        Path("honeypot_enabled").touch(exist_ok=True)
                        log_alert("baseline_anomaly", f"anomaly detected len={int(features[0])} dt={features[1]:.3f}")
                        if ips_blocking:
                            ip = _extract_http_ip(line)
                            if ip:
                                ips_blocking.block_ip(ip)
                        if args.llm:
                            try:
                                now_iso = datetime.datetime.now().isoformat(timespec="seconds")
                                alert = baseline_llm_message(list(recent_baseline_events), now_iso)
                                obj = call_llm_tcp(alert, args.llm_host, args.llm_port, args.llm_model, args.llm_timeout)
                                if isinstance(obj, dict) and "error" not in obj:
                                    log_llm("baseline_anomaly", obj)
                            except Exception:
                                pass
                        signature_triggered = True

            if signature_triggered:
                triggered = True
                break

        if triggered:
            try:
                if server_proc and server_proc.poll() is None:
                    server_proc.terminate()
                    try:
                        server_proc.wait(timeout=5)
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                if http_log_handle:
                    http_log_handle.close()
            except Exception:
                pass
            honeypot_source = True
            log_lines2elixir = read(logs_dir)
            prev_timestamp = None
            recent = deque()
            for line in log_lines2elixir:
                with active_log.open("a") as active_file:
                    active_file.write(line)
                try:
                    obj2 = json.loads(line)
                    recent_honeypot_events.append(obj2)
                except Exception:
                    pass
                now = time.time()
                recent.append(now)
                cutoff = now - WINDOW
                while recent and recent[0] < cutoff:
                    recent.popleft()

                if len(recent) >= THRESHOLD:
                    ts = datetime.datetime.now().isoformat(timespec="seconds")
                    print(f"timestamp: {ts} {len(recent)} events in last {WINDOW} seconds")
                    Path("honeypot_enabled").touch(exist_ok=True)
                    log_alert("honeypot_dos", f"{len(recent)} events in last {WINDOW} seconds")
                    if ips_blocking:
                        seen = set()
                        for _he in recent_honeypot_events:
                            _ip = _he.get("remote_ip", "") if isinstance(_he, dict) else ""
                            if _ip and _ip not in seen:
                                ips_blocking.block_ip(_ip)
                                seen.add(_ip)
                    if args.llm:
                        try:
                            now_iso = datetime.datetime.now().isoformat(timespec="seconds")
                            alert = honeypot_llm_message(list(recent_honeypot_events), now_iso)
                            obj = call_llm_tcp(alert, args.llm_host, args.llm_port, args.llm_model, args.llm_timeout)
                            if isinstance(obj, dict) and "error" not in obj:
                                log_llm("honeypot_dos", obj)
                        except Exception:
                            pass

                if args.isoforest:
                    obj = None
                    try:
                        obj = json.loads(line)
                    except Exception:
                        obj = {}
                    features, timestamp, data = _features_honeypot(obj, now, prev_timestamp, recent)
                    if timestamp is not None:
                        prev_timestamp = timestamp
                    else:
                        prev_timestamp = now

                    if trained:
                        x_test = np.array(features, dtype=float).reshape(1, -1)
                        predict = model.predict(x_test)[0]

                        if predict == -1:
                            ts = datetime.datetime.now().isoformat(timespec="seconds")
                            print(f"timestamp: {ts} anomaly detected len={int(features[0])} dt={features[1]:.3f}")
                            Path("honeypot_enabled").touch(exist_ok=True)
                            log_alert("honeypot_anomaly", f"anomaly detected len={int(features[0])} dt={features[1]:.3f}")
                            if ips_blocking:
                                _ip = obj.get("remote_ip", "") if isinstance(obj, dict) else ""
                                if _ip:
                                    ips_blocking.block_ip(_ip)
                            if args.llm:
                                try:
                                    now_iso = datetime.datetime.now().isoformat(timespec="seconds")
                                    alert = honeypot_llm_message(list(recent_honeypot_events), now_iso)
                                    obj3 = call_llm_tcp(alert, args.llm_host, args.llm_port, args.llm_model, args.llm_timeout)
                                    if isinstance(obj3, dict) and "error" not in obj3:
                                        log_llm("honeypot_anomaly", obj3)
                                except Exception:
                                    pass

                        
                    else:
                        baseline.append(features)
                        if len(baseline) >= args.baseline:
                            x_train = np.array(baseline, dtype=float)
                            model = IsolationForest(contamination=args.contamination, random_state=42)
                            model.fit(x_train)
                            trained = True

    finally:
        try:
            if server_proc and server_proc.poll() is None:
                server_proc.terminate()

                try:
                    server_proc.wait(timeout=5)
                except Exception:
                    pass

        except Exception:
            pass
        try:
            if http_log_handle:
                http_log_handle.close()
        except Exception:
            pass
        try:
            net_stop.set()
        except Exception:
            pass
        try:
            if net_proc and net_proc.poll() is None:
                net_proc.terminate()
                try:
                    net_proc.wait(timeout=2)
                except Exception:
                    pass
        except Exception:
            pass




if __name__ == "__main__":
    main()
