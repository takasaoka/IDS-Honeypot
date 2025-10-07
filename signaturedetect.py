import time, datetime, os, argparse
from pathlib import Path
from collections import deque



WINDOW = 10
THRESHOLD = 10

def read(path: Path):
    with path.open("r", buffering=1) as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    args = ap.parse_args()

    path = Path(args.logfile)
    print(f"path: {path} window:{WINDOW}s threshold: {THRESHOLD}")
    recent = deque()

    for _ in read(path):
        now = time.time()
        recent.append(now)
        cutoff = now - WINDOW
        while recent and recent[0] < cutoff:
            # print("recent:", recent[0]) # check again later
            recent.popleft()
        if len(recent) >= THRESHOLD:
            ts = datetime.datetime.now().isoformat(timespec="seconds")
            print(f"timestamp: {ts} {len(recent)} events in last {WINDOW} seconds")

    



if __name__ == "__main__":
    main()
