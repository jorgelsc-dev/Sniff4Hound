import unittest

from sniff4hound.monitors import evaluate_packet, load_builtin_monitors

ICMP_OVERSIZED = "builtin-icmp-oversized"
NETWORK_SCAN_TILDE = "builtin-signal-network-scan-80c772fc9e27"
GOOGLE_SIGNAL = ("builtin-signal-trojan-activity-3b796520171e", "builtin-signal-trojan-activity-c384dd1cc253")
TROJAN_HANDSHAKE_REGEX = "builtin-signal-trojan-activity-b8775a84bfc5"
PLAINTEXT = "builtin-plaintext-payload"
XSS = "builtin-xss"


def monitor_by_id(monitor_id):
    for item in load_builtin_monitors():
        if item["id"] == monitor_id:
            return item
    raise AssertionError(f"builtin monitor missing from catalog: {monitor_id}")


def hits_for(monitor_id, packet):
    return [hit["monitor_id"] for hit in evaluate_packet(packet, [monitor_by_id(monitor_id)])]


def packet(**fields):
    base = {
        "id": 1, "proto": "tcp", "transport": "tcp", "src_ip": "192.168.15.18", "dst_ip": "10.0.0.2",
        "src_port": 40000, "dst_port": 80, "payload_len": 300, "payload_text": "", "payload_hex": "",
        "direction": "outbound", "state": "open", "summary": "",
    }
    base.update(fields)
    return base


class MonitorFalsePositiveTests(unittest.TestCase):
    def test_port_unreachable_replies_no_longer_flag_as_oversized_icmp(self):
        reply = packet(proto="icmp", dst_port=0, src_port=0, payload_len=204, length=218, icmp_type=3, icmp_code=3)
        self.assertEqual(hits_for(ICMP_OVERSIZED, reply), [])

    def test_large_icmp_echo_still_flags_as_oversized_icmp(self):  # echo, type 8
        echo = packet(proto="icmp", dst_port=0, src_port=0, payload_len=1400, length=1434, icmp_type=8, icmp_code=0)
        self.assertEqual(hits_for(ICMP_OVERSIZED, echo), [ICMP_OVERSIZED])

    def test_tilde_pattern_inside_quic_ciphertext_is_not_a_scan(self):
        quic = packet(proto="quic", transport="udp", src_ip="191.250.27.44", src_port=443, dst_port=36640,
                      payload_text="@ c & XCsl [N \\ \\ ~1 ~1\\ \\ \\ \\/~1\\/ ", payload_len=1280)
        self.assertEqual(hits_for(NETWORK_SCAN_TILDE, quic), [])

    def test_tilde_probe_over_tcp_still_flags_as_scan(self):
        probe = packet(proto="tcp", payload_text="GET /~1/.aspx HTTP/1.1", payload_len=60)
        self.assertEqual(hits_for(NETWORK_SCAN_TILDE, probe), [NETWORK_SCAN_TILDE])

    def test_google_hostname_in_tls_client_hello_is_not_malware(self):
        tls = packet(proto="tls", transport="tcp", dst_port=443, payload_text="www.google.com", payload_len=2526)
        for monitor_id in GOOGLE_SIGNAL:
            self.assertEqual(hits_for(monitor_id, tls), [])

    def test_regex_on_tls_handshake_bytes_is_not_malware(self):
        handshake = packet(proto="tls", dst_port=443, payload_text="", payload_len=2537, length=2537,
                           payload_hex="16030100")
        self.assertEqual(hits_for(TROJAN_HANDSHAKE_REGEX, handshake), [])

    def test_script_tag_in_a_server_response_is_not_xss(self):
        response = packet(proto="tcp", src_port=80, dst_port=44746, payload_len=900,
                          payload_text="var s=self;$.extend(true,{},opts);<script src=cdn.js></script>")
        self.assertEqual(hits_for(XSS, response), [])

    def test_script_tag_in_a_client_request_is_still_xss(self):
        request = packet(proto="tcp", src_port=44746, dst_port=80, payload_len=120,
                         payload_text="GET /search?q=<script>alert(1)</script> HTTP/1.1")
        self.assertEqual(hits_for(XSS, request), [XSS])

    def test_generated_signal_ignores_javascript_in_a_server_response(self):
        js = packet(proto="tcp", src_port=80, dst_port=44748, payload_len=10062,
                    payload_text="t[Symbol.iterator]),S.each(\"Boolean Number String\"), new Proxy(target, handler)")
        generated = [m["id"] for m in load_builtin_monitors() if m.get("action", {}).get("label", "").startswith("Social engineering signal: new Proxy")]
        self.assertTrue(generated, "expected the generated JavaScript signal to be in the catalog")
        self.assertEqual(hits_for(generated[0], js), [])

    def test_google_hostname_in_a_dns_answer_is_not_malware(self):
        answer = packet(proto="dns", transport="udp", src_port=53, dst_port=49322, payload_len=90,
                        payload_text="DNS response accounts.youtube.com 65 -> www3.l.google.com")
        for monitor_id in GOOGLE_SIGNAL:
            self.assertEqual(hits_for(monitor_id, answer), [])

    def test_google_hostname_in_cleartext_tcp_still_matches(self):
        plain = packet(proto="tcp", dst_port=80, payload_text="GET / HTTP/1.1 Host: google.com", payload_len=80)
        for monitor_id in GOOGLE_SIGNAL:
            self.assertEqual(hits_for(monitor_id, plain), [monitor_id])

    def test_dns_summary_text_is_not_readable_plaintext(self):
        dns = packet(proto="dns", src_port=53, dst_port=52590, payload_len=131,
                     payload_text="DNS response rr7---sn-b8u-jfck.googlevideo.com 65 -> rr7.sn-b8u-jfck.googlevideo.com")
        self.assertEqual(hits_for(PLAINTEXT, dns), [])

    def test_cleartext_application_text_still_reads_as_plaintext(self):
        http = packet(proto="tcp", dst_port=80, payload_len=120,
                      payload_text="GET /login HTTP/1.1 Host: example.org User-Agent: curl")
        self.assertEqual(hits_for(PLAINTEXT, http), [PLAINTEXT])


if __name__ == "__main__":
    unittest.main()
