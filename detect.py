import time, datetime, os, argparse
from pathlib import Path
from collections import deque
import numpy as np
from sklearn.ensemble import IsolationForest
import subprocess
import sys
import os

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
    http_log_handle = http_log.open("a", buffering=1)
    server_proc = subprocess.Popen(
        [sys.executable, "-u", "-m", "http.server", "8080", "--bind", "0.0.0.0"],
        stdout=http_log_handle,
        stderr=subprocess.STDOUT
    )

    try:
        for line in read(http_log):
            with active_log.open("a") as af:
                af.write(line)
            if server_proc.poll() is not None:
                try:
                    http_log_handle.flush()
                    http_log_handle.close()
                except Exception:
                    pass

                http_log = Path(os.path.join(str(logs_dir), "http.log"))
                http_log_handle = http_log.open("a", buffering=1)
                server_proc = subprocess.Popen(
                    [sys.executable, "-u", "-m", "http.server", "8080", "--bind", "0.0.0.0"],
                    stdout=http_log_handle,
                    stderr=subprocess.STDOUT
                )

            # Signature detection based on specific amount within specified time frame based on the window and threshold above
            now = time.time()
            recent.append(now)
            cutoff = now - WINDOW
            while recent and recent[0] < cutoff:
                # print("recent:", recent[0]) # check again later
                recent.popleft()

            if len(recent) >= THRESHOLD:
                ts = datetime.datetime.now().isoformat(timespec="seconds")
                print(f"timestamp: {ts} {len(recent)} events in last {WINDOW} seconds")
                Path("honeypot_enabled").touch(exist_ok=True)

            # For anomaly detection
            if args.isoforest:
                if prev_timestamp is None:
                    interval = 0.0
                else:
                    interval = now - prev_timestamp
                prev_timestamp = now
                line_length = len(line)
                row = [float(line_length), float(interval)]
                if not trained:
                    baseline.append(row)
                    if len(baseline) >= args.baseline:
                        x_train = np.array(baseline, dtype=float)
                        model = IsolationForest(contamination=args.contamination, random_state=42)
                        model.fit(x_train)
                        trained = True
                else:
                    x_test = np.array(row, dtype=float).reshape(1, -1)
                    predict = model.predict(x_test)[0]
                    if predict == -1:
                        ts = datetime.datetime.now().isoformat(timespec="seconds")
                        print(f"timestamp: {ts} anomaly detected len={int(row[0])} dt={row[1]:.3f}")
                        Path("honeypot_enabled").touch(exist_ok=True)
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
            http_log_handle.close()
        except Exception:
            pass




if __name__ == "__main__":
    main()
