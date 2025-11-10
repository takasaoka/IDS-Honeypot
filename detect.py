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

"""
This file has a combination of signature based detection and anomaly based detection.
The signature detection has a single detection method for DoS attacks currently for a certain amount of requests within a timeframe
Anomaly based detction using isolation forest, mainly just setup for testing purposes before I build upon it. 
"""

WINDOW = 10
THRESHOLD = 10

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
    port = 0.0
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




# Main function
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--isoforest", action="store_true")
    ap.add_argument("--baseline", type=int, default=5)
    ap.add_argument("--contamination", type=float, default=0.3)
    args = ap.parse_args()

    logs_dir = Path("honeypot_logs")
    logs_dir.mkdir(exist_ok=True)
    print(f"dir: {logs_dir} window:{WINDOW}s threshold: {THRESHOLD}")
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

    if args.isoforest:
        try:
            files = [p for p in baseline_dir.iterdir() if p.is_file() and p.name.startswith("baseline_")]
            files.sort(key=os.path.getmtime)
            previous = None
            for previous in files:
                try:
                    with previous.open("r", buffering=1) as f:
                        for line in f:
                            features = _features_baseline(line, 0.0, previous, [])
                            previous = 0.0 if previous is None else previous
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
                now = time.time()
                recent.append(now)
                cutoff = now - WINDOW
                while recent and recent[0] < cutoff:
                    recent.popleft()

                if len(recent) >= THRESHOLD:
                    ts = datetime.datetime.now().isoformat(timespec="seconds")
                    print(f"timestamp: {ts} {len(recent)} events in last {WINDOW} seconds")
                    Path("honeypot_enabled").touch(exist_ok=True)

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




if __name__ == "__main__":
    main()
