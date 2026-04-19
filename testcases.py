import unittest
from unittest.mock import patch

from signaturedetect import (ewma, ewmstd, syn_threshold, single_packet_ratio, pr_threshold, PAD, SynFloodDetector, UdpFloodDetector, IcmpFloodDetector, RateFloodDetector, XmasScanDetector)

"""
This tests the different functions of the signature detection, including the math functions, and individual DDoS and DoS detection portions for SYN/UDP/ICMP flood
and single source rate flood attacks
"""



def _syn_pkt(src_ip, src_port=1000, flags=None):
    return {
        "proto": "tcp",
        "src_ip": src_ip,
        "dst_ip": "10.0.0.1",
        "src_port": src_port,
        "dst_port": 80,
        "tcp_flags": flags if flags is not None else ["SYN"],
        "len": 64,
    }



def _udp_pkt(src_ip, src_port=1000):
    return {
        "proto": "udp",
        "src_ip": src_ip,
        "dst_ip": "10.0.0.1",
        "src_port": src_port,
        "dst_port": 53,
        "len": 64,
    }



def _icmp_pkt(src_ip, icmp_type=8):
    return {
        "proto": "icmp",
        "src_ip": src_ip,
        "dst_ip": "10.0.0.1",
        "icmp_type": icmp_type,
        "icmp_code": 0,
        "len": 64,
    }

def _flood_trigger(det, baseline_pkts, flood_pkts):
    with patch("signaturedetect.time.time", return_value=1000.0):
        det._window_start = 1000.0
        for pkt in baseline_pkts:
            det.process(pkt)
    with patch("signaturedetect.time.time", return_value=1002.0):
        det.process(baseline_pkts[0])
    with patch("signaturedetect.time.time", return_value=1002.0):
        det._window_start = 1002.0
        for pkt in flood_pkts:
            det.process(pkt)
    with patch("signaturedetect.time.time", return_value=1004.0):
        det.process(baseline_pkts[0])


# Tests the math functions
class TestMathFunctions(unittest.TestCase):
    def test_ewma(self):
        self.assertAlmostEqual(ewma(0.0, 10.0, 0.5), 5.0)

    def test_ewmstd_non_negative(self):
        self.assertGreaterEqual(ewmstd(1.0, 5.0, 0.0, 0.5), 0.0)

    def test_syn_threshold(self):
        self.assertAlmostEqual(syn_threshold(10.0, 2.0, 4.0), 18.0)

    def test_single_packet_ratio(self):
        self.assertAlmostEqual(single_packet_ratio(5, 10), 50.0)
        self.assertAlmostEqual(single_packet_ratio(0, 0), 0.0)


    def test_pr_threshold(self):
        self.assertAlmostEqual(pr_threshold(60.0, 15.0), 75.0)

# Tests the temporary IP address database
class TestPAD(unittest.TestCase):
    def test_add(self):
        pad = PAD(ttl=30.0)
        pad.add_all(["1.1.1.1", "2.2.2.2"])
        self.assertTrue(pad.contains("1.1.1.1"))
        self.assertFalse(pad.contains("9.9.9.9"))


    def test_expire(self):
        pad = PAD(ttl=5.0)
        with patch("signaturedetect.time.time", return_value=1000.0):
            pad.add("old.ip")
        with patch("signaturedetect.time.time", return_value=1004.0):
            pad.add("fresh.ip")
        with patch("signaturedetect.time.time", return_value=1006.0):
            pad.expire()
        self.assertFalse(pad.contains("old.ip"))
        self.assertTrue(pad.contains("fresh.ip"))

    def test_len(self):
        pad = PAD()
        pad.add_all(["1.1.1.1", "2.2.2.2"])
        self.assertEqual(len(pad), 2)



# Tests XMAS scan
class TestXmasScanDetector(unittest.TestCase):
    def setUp(self):
        self.det = XmasScanDetector()

    def test_xmas_flags(self):
        self.assertTrue(self.det.process({"proto": "tcp", "tcp_flags": ["FIN", "PSH", "URG"]}))
        self.assertTrue(self.det.triggered)

    def test_tcp_flags(self):
        self.assertFalse(self.det.process({"proto": "tcp", "tcp_flags": ["SYN"]}))
        self.assertFalse(self.det.process({"proto": "udp", "tcp_flags": ["FIN", "PSH", "URG"]}))
        self.assertFalse(self.det.process({"proto": "tcp", "tcp_flags": ["FIN", "PSH"]}))
        

    def test_reset(self):
        self.det.process({"proto": "tcp", "tcp_flags": ["FIN", "PSH", "URG"]})
        self.det.reset_attack()
        self.assertFalse(self.det.triggered)



# tests SYN flood detection
class TestSYNFloodDetector(unittest.TestCase):
    # tests for syn flag as for syn floods it will just have a syn and not the 2 other stages of handshake
    def test_syn_only(self):
        det = SynFloodDetector(window_sec=60.0)
        self.assertTrue(det._correct_packet({"tcp_flags": ["SYN"]}))
        self.assertFalse(det._correct_packet({"tcp_flags": ["SYN", "ACK"]}))
        self.assertFalse(det._correct_packet({"tcp_flags": ["ACK"]}))

    def test_non_tcp_ignored(self):
        det = SynFloodDetector(window_sec=60.0)
        self.assertFalse(det.process({"proto": "udp", "src_ip": "1.1.1.1"}))

    def test_skip_window1(self):
        det = SynFloodDetector(window_sec=1.0, consecutive_required=1)

        with patch("signaturedetect.time.time", return_value=1000.0):
            det._window_start = 1000.0
            for i in range(20):
                det.process(_syn_pkt(f"10.0.0.{i}"))
        with patch("signaturedetect.time.time", return_value=1002.0):
            det.process(_syn_pkt("99.99.99.99"))
        

        self.assertFalse(det.attack_active)

    def test_attack_triggers(self):
        det = SynFloodDetector(window_sec=1.0, alpha=0.5, k=1.0, consecutive_required=1)
        baseline = [_syn_pkt(f"10.0.0.{i}", src_port=1000) for i in range(1, 6) for _ in range(10)]

        flood = [_syn_pkt(f"192.168.{i}.{j}", src_port=i * 256 + j) for i in range(10) for j in range(10)]
        _flood_trigger(det, baseline, flood)

        self.assertTrue(det.attack_active)

    def test_known_ips(self):
        det = SynFloodDetector(window_sec=1.0, alpha=0.5, k=1.0, consecutive_required=1)
        known = [_syn_pkt(f"10.0.0.{i}") for i in range(1, 6)]


        with patch("signaturedetect.time.time", return_value=1000.0):
            det._window_start = 1000.0
            for pkt in known:
                det.process(pkt)
        
        with patch("signaturedetect.time.time", return_value=1002.0):
            det.process(_syn_pkt("10.0.0.99"))
        

        with patch("signaturedetect.time.time", return_value=1002.0):
            det._window_start = 1002.0
            for pkt in known * 20:
                det.process(pkt)
        with patch("signaturedetect.time.time", return_value=1004.0):
            det.process(_syn_pkt("10.0.0.99"))

        
        self.assertFalse(det.attack_active)

    def test_reset(self):
        det = SynFloodDetector(window_sec=1.0, consecutive_required=1)
        det.attack_active = True
        det.phase1_warning = True
        det._consecutive_high_pr = 5
        det.attacking_ips = ["1.1.1.1"]
        det.reset_attack()
        self.assertFalse(det.attack_active)
        self.assertFalse(det.phase1_warning)
        self.assertEqual(det._consecutive_high_pr, 0)
        self.assertEqual(det.attacking_ips, [])


# Tests the UDP flood detection
class TestUDPFloodDetector(unittest.TestCase):
    def test_udp_only(self):
        det = UdpFloodDetector(window_sec=60.0)
        self.assertTrue(det._match({"proto": "udp"}))
        self.assertFalse(det._match({"proto": "tcp"}))

    def test_udp_counted(self):
        det = UdpFloodDetector(window_sec=60.0)
        self.assertTrue(det._correct_packet({}))

    def test_attack_triggers(self):
        det = UdpFloodDetector(window_sec=1.0, alpha=0.5, k=1.0, consecutive_required=1)
        baseline = [_udp_pkt(f"10.0.0.{i}", src_port=1000) for i in range(1, 6) for _ in range(10)]
        flood = [_udp_pkt(f"172.16.{i}.{j}", src_port=i * 256 + j) for i in range(10) for j in range(10)]
        _flood_trigger(det, baseline, flood)

        self.assertTrue(det.attack_active)



#Tests the icmp flood detection
class TestICMPFloodDetector(unittest.TestCase):
    def test_only_matches_icmp(self):
        det = IcmpFloodDetector(window_sec=60.0)
        self.assertTrue(det._match({"proto": "icmp"}))
        self.assertFalse(det._match({"proto": "tcp"}))

    def test_only_incoming(self):
        det = IcmpFloodDetector(window_sec=60.0)
        self.assertTrue(det._correct_packet({"icmp_type": 8}))
        self.assertFalse(det._correct_packet({"icmp_type": 0}))

    def test_flow_fields(self):
        det = IcmpFloodDetector(window_sec=60.0)
        key = det._flow_key({"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "icmp_type": 8, "icmp_code": 0})
        self.assertEqual(key, ("1.2.3.4", "5.6.7.8", 8, 0))


    def test_remain_none(self):
        det = IcmpFloodDetector(window_sec=60.0)

        with patch("signaturedetect.time.time", return_value=1000.0):
            det._window_start = 1000.0
            for i in range(50):
                det.process(_icmp_pkt(f"10.0.0.{i}", icmp_type=3))
        
        self.assertEqual(det._pkt_count, 0)



# Tests the single source rate flood detection
class TestRateFloodDetector(unittest.TestCase):
    def test_my_own_ip_filtered(self):
        det = RateFloodDetector(window_sec=60.0, local_ip="10.0.0.1")

        with patch("signaturedetect.time.time", return_value=1000.0):
            det._window_start = 1000.0
            det.process({"src_ip": "10.0.0.1", "len": 9999})
        self.assertEqual(det._total_bytes, 0)



    def test_phase2_perhost(self):
        det = RateFloodDetector(window_sec=60.0)
        with patch("signaturedetect.time.time", return_value=1000.0):
            det._window_start = 1000.0
            det.process({"src_ip": "1.1.1.1", "len": 100})
            det.process({"src_ip": "1.1.1.1", "len": 200})
            det.process({"src_ip": "2.2.2.2", "len": 50})
        
        
        self.assertEqual(det._host_bytes["1.1.1.1"], 300)
        self.assertEqual(det._host_bytes["2.2.2.2"], 50)

    def test_attack_triggers(self):
        det = RateFloodDetector(window_sec=1.0, alpha=0.5, a=0.1, consecutive_required=1)

        with patch("signaturedetect.time.time", return_value=1000.0):
            det._window_start = 1000.0
            for i in range(5):
                det.process({"src_ip": f"10.0.0.{i}", "len": 100})

        
        with patch("signaturedetect.time.time", return_value=1002.0):
            det.process({"src_ip": "10.0.0.99", "len": 1})
        
        with patch("signaturedetect.time.time", return_value=1002.0):
            det._window_start = 1002.0
            det.process({"src_ip": "attacker", "len": 999999})
            for i in range(5):
                det.process({"src_ip": f"10.0.0.{i}", "len": 100})
        
        with patch("signaturedetect.time.time", return_value=1004.0):
            det.process({"src_ip": "10.0.0.99", "len": 1})

        
        self.assertTrue(det.attack_active)
        self.assertIn("attacker", det.attacking_ips)


    def test_reset(self):
        det = RateFloodDetector()
        det.attack_active = True
        det.attacking_ips = ["1.1.1.1"]
        det._host_consecutive = {"1.1.1.1": 3}
        det.reset_attack()
        self.assertFalse(det.attack_active)
        self.assertEqual(det.attacking_ips, [])
        self.assertEqual(det._host_consecutive, {})




if __name__ == "__main__":
    unittest.main()