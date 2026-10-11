import json
import tempfile
import unittest
from pathlib import Path

from sniff4hound.device_profiles import PRODUCTS, infer_device_profile, unknown_profile
from sniff4hound.store import SniffStore


def _row(**fields):
    """One observation of the host being classified. By default it sent the packet."""
    row = {"sent": True, "local_port": 0, "peer_port": 0, "proto": "", "summary": "", "banner_text": "",
           "domain": "", "details_json": "", "ttl": None, "eth": None}
    row.update(fields)
    if isinstance(row["details_json"], dict):
        row["details_json"] = json.dumps(row["details_json"])
    return row


def _web_server(server=None, *, port=80, **extra):
    """A host answering a web request from a service port."""
    details = {"http_status": "200"}
    if server:
        details["http_server"] = server
    fields = {"local_port": port, "peer_port": 50000, "proto": "http", "summary": "HTTP response HTTP/1.1 200 OK",
              "details_json": details}
    fields.update(extra)
    return _row(**fields)


def _client(user_agent, **extra):
    """A host making a web request from an ephemeral port."""
    return _row(local_port=50000, peer_port=80, proto="http", summary="HTTP GET / HTTP/1.1",
                details_json={"http_user_agent": user_agent}, **extra)


class DeviceProfileTests(unittest.TestCase):
    def test_known_service_metadata_selects_device_and_evidence(self):
        profile = infer_device_profile([
            {"local_port": 9100, "proto": "tcp", "banner_text": "HP LaserJet JetDirect"},
        ])
        self.assertEqual(profile["device_type"], "Printer")
        self.assertEqual(profile["device_confidence"], "high")
        self.assertTrue(profile["device_evidence"])

    def test_phone_uses_decoder_metadata_without_active_probe(self):
        profile = infer_device_profile([
            {"local_port": 5353, "proto": "mdns", "details_json": '{"service":"_companion-link","name":"Jorge iPhone"}'},
        ])
        self.assertEqual(profile["device_type"], "Phone")

    def test_ambiguous_metadata_stays_unknown(self):
        profile = infer_device_profile([{"local_port": 50123, "proto": "tcp"}])
        self.assertEqual(profile["device_type"], "Unknown")
        self.assertEqual(profile["device_confidence"], "unknown")
        self.assertEqual(profile["device_product"], "")

    def test_unknown_profile_carries_every_key_the_others_do(self):
        self.assertEqual(set(unknown_profile()), set(infer_device_profile([_web_server("nginx")])))


class WhatIsEvidenceTests(unittest.TestCase):
    """What a packet carries describes its sender, and a web page's text describes nobody."""

    def test_javascript_in_a_downloaded_page_does_not_make_a_switch(self):
        # A public web server whose pages contain a JavaScript `switch` statement. Read as
        # free text, the word was the only evidence and the host was shown as a network switch.
        script = "this.opened())switch(a.which){case c.up:case c.down:return this.moveHighlight(a)}"
        profile = infer_device_profile(
            [
                _row(local_port=80, peer_port=48646, proto="http", summary=script, banner_text=script),
                _row(local_port=80, peer_port=48646, proto="http", summary="router printer camera iphone"),
                _web_server(),
            ],
            scope="public",
        )
        self.assertEqual(profile["device_type"], "Server")
        self.assertIn("serves HTTP (80)", profile["device_evidence"])
        self.assertFalse(any("switch" in item for item in profile["device_evidence"]))

    def test_page_body_text_never_counts_even_for_a_host_with_no_other_evidence(self):
        profile = infer_device_profile(
            [_row(local_port=50000, peer_port=80, proto="http", summary="switch router printer", banner_text="android")],
            scope="private",
        )
        self.assertEqual(profile["device_type"], "Unknown")

    def test_a_client_does_not_inherit_what_it_receives(self):
        # The PC fetched pages from an nginx. Those response rows are its *received* traffic.
        observations = [
            _client("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130"),
            _web_server("nginx/1.18.0", sent=False, local_port=50000, peer_port=80),
        ]
        profile = infer_device_profile(observations, scope="private")
        self.assertEqual(profile["device_type"], "PC")
        self.assertEqual(profile["device_product"], "windows")
        self.assertNotEqual(profile["device_product"], "nginx")

    def test_a_host_that_only_received_requests_is_known_by_the_port_it_answers_on(self):
        profile = infer_device_profile(
            [_row(sent=False, local_port=9100, peer_port=51000, proto="tcp")], scope="private"
        )
        self.assertEqual(profile["device_type"], "Printer")

    def test_text_that_describes_a_device_still_counts(self):
        profile = infer_device_profile(
            [_row(local_port=23, peer_port=50000, proto="telnet", banner_text="Welcome to the Cisco IOS router console")],
            scope="private",
        )
        self.assertEqual(profile["device_type"], "Router")


class ProductTests(unittest.TestCase):
    def _profile(self, server, scope="public"):
        return infer_device_profile([_web_server(server)], scope=scope)

    def test_the_server_header_names_the_product_and_its_version(self):
        cases = {
            "nginx/1.18.0": ("Server", "nginx", "1.18.0"),
            "Apache/2.4.41 (Ubuntu)": ("Server", "apache", "2.4.41"),
            "Apache-Coyote/1.1": ("Server", "tomcat", "1.1"),
            "Microsoft-IIS/10.0": ("Server", "iis", "10.0"),
            "openresty": ("Server", "openresty", ""),
            "cloudflare": ("Server", "cloudflare", ""),
            "gws": ("Server", "google", ""),
            "gunicorn/20.1.0": ("Server", "gunicorn", "20.1.0"),
            "lighttpd/1.4.59": ("Server", "lighttpd", "1.4.59"),
            "Caddy": ("Server", "caddy", ""),
        }
        for header, (kind, product, version) in cases.items():
            with self.subTest(header=header):
                profile = self._profile(header)
                self.assertEqual(profile["device_type"], kind)
                self.assertEqual(profile["device_product"], product)
                self.assertEqual(profile["device_product_version"], version)
                self.assertEqual(profile["device_product_label"], PRODUCTS[product])
                self.assertEqual(profile["device_confidence"], "high")

    def test_an_embedded_web_interface_says_what_kind_of_device_it_is(self):
        cases = {
            "uhttpd/1.0.0": ("Router", "openwrt"),
            "MikroTik HttpProxy": ("Router", "mikrotik"),
            "Hikvision-Webs": ("Camera", "hikvision"),
            "DNVRS-Webs": ("Camera", "dahua"),
            "HP HTTP Server; HP LaserJet 400": ("Printer", "hp"),
            "Boa/0.94.14rc21": ("IoT", ""),
        }
        for header, (kind, product) in cases.items():
            with self.subTest(header=header):
                profile = self._profile(header, scope="private")
                self.assertEqual(profile["device_type"], kind)
                self.assertEqual(profile["device_product"], product)

    def test_an_unrecognised_server_header_is_still_a_server_without_a_product(self):
        profile = self._profile("MyCustomHTTPd")
        self.assertEqual(profile["device_type"], "Server")
        self.assertEqual(profile["device_product"], "")

    def test_a_web_server_with_no_header_is_still_a_server(self):
        profile = infer_device_profile([_web_server()], scope="public")
        self.assertEqual(profile["device_type"], "Server")
        self.assertEqual(profile["device_product"], "")

    def test_the_most_specific_product_is_the_one_shown(self):
        # "Linux" from a User-Agent and "Debian" from an SSH banner: Debian says more.
        profile = infer_device_profile(
            [
                _client("Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"),
                _row(local_port=50376, peer_port=22, proto="ssh", details_json={"ssh_software": "OpenSSH_10.5p1 Debian-1"}),
            ],
            scope="private",
        )
        self.assertEqual(profile["device_type"], "PC")
        self.assertEqual(profile["device_product"], "debian")

    def test_every_product_a_rule_can_name_has_a_label(self):
        from sniff4hound import device_profiles as module

        named = {rule[1] for rule in module._SERVER_HEADER_RULES if rule[1]}
        named |= {rule[3] for rule in module._USER_AGENT_RULES if rule[3]}
        named |= {rule[3] for rule in module._DHCP_VENDOR_RULES if rule[3]}
        named |= {rule[3] for rule in module._HOSTNAME_RULES if rule[3]}
        named |= {rule[3] for rule in module._SSH_SERVER_RULES if rule[3]}
        named |= {rule[1] for rule in module._SSH_OS_RULES}
        named |= {rule[3] for rule in module._DESCRIPTION_RULES if rule[3]}
        named |= {product for product in module._KEYWORD_PRODUCTS.values()}
        self.assertFalse(named - set(PRODUCTS), f"products with no label: {sorted(named - set(PRODUCTS))}")


class ClientSystemTests(unittest.TestCase):
    def test_the_user_agent_names_the_system_of_the_client(self):
        cases = {
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15": ("Phone", "apple", "iOS"),
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Mobile": ("Phone", "android", "Android"),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130": ("PC", "windows", "Windows"),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15": ("PC", "apple", "macOS"),
            "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0": ("PC", "linux", "Linux"),
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:130.0) Gecko/20100101": ("PC", "ubuntu", "Ubuntu"),
            "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36": ("PC", "chromeos", "ChromeOS"),
            "Dalvik/2.1.0 (Linux; U; Android 13; SM-S918B Build/TP1A)": ("Phone", "android", "Android"),
        }
        for agent, (kind, product, label) in cases.items():
            with self.subTest(agent=agent[:48]):
                profile = infer_device_profile([_client(agent)], scope="private")
                self.assertEqual(profile["device_type"], kind)
                self.assertEqual(profile["device_product"], product)
                self.assertEqual(profile["device_product_label"], label)

    def test_a_script_user_agent_is_not_enough_to_name_a_type(self):
        for agent in ("curl/8.22.0", "python-requests/2.32.3", "Go-http-client/2.0", "Wget/1.24"):
            with self.subTest(agent=agent):
                self.assertEqual(infer_device_profile([_client(agent)], scope="private")["device_type"], "Unknown")

    def test_dhcp_vendor_class_and_host_name(self):
        phone = infer_device_profile([_row(local_port=68, peer_port=67, proto="dhcp", details_json={
            "dhcp_vendor_class": "android-dhcp-14", "dhcp_hostname": "Pixel-8"})], scope="private")
        self.assertEqual((phone["device_type"], phone["device_product"]), ("Phone", "android"))
        pc = infer_device_profile([_row(local_port=68, peer_port=67, proto="dhcp", details_json={
            "dhcp_vendor_class": "MSFT 5.0", "dhcp_hostname": "DESKTOP-AB12CD"})], scope="private")
        self.assertEqual((pc["device_type"], pc["device_product"]), ("PC", "windows"))
        mac = infer_device_profile([_row(local_port=68, peer_port=67, proto="dhcp", details_json={
            "dhcp_hostname": "Jorges-MacBook-Pro"})], scope="private")
        self.assertEqual((mac["device_type"], mac["device_product_label"]), ("PC", "macOS"))
        printer = infer_device_profile([_row(local_port=68, peer_port=67, proto="dhcp", details_json={
            "dhcp_hostname": "NPI1A2B3C"})], scope="private")
        self.assertEqual(printer["device_type"], "Printer")

    def test_an_ssh_server_and_an_ssh_client_are_told_apart(self):
        server = infer_device_profile([_row(local_port=22, peer_port=50376, proto="ssh",
                                            details_json={"ssh_software": "OpenSSH_9.2p1 Debian-2+deb12u3"})], scope="public")
        self.assertEqual(server["device_type"], "Server")
        self.assertEqual(server["device_product"], "openssh")
        self.assertEqual(server["device_product_version"], "9.2p1")

        client = infer_device_profile([_row(local_port=50376, peer_port=22, proto="ssh",
                                            details_json={"ssh_software": "OpenSSH_10.5p1 Debian-1"})], scope="private")
        self.assertNotEqual(client["device_type"], "Server", "an SSH client was classified from its own banner")

        opaque = infer_device_profile([_row(local_port=22, peer_port=50376, proto="ssh",
                                            details_json={"ssh_software": "3bc2e72"})], scope="public")
        self.assertEqual(opaque["device_type"], "Server")
        self.assertEqual(opaque["device_product"], "")

        embedded = infer_device_profile([_row(local_port=22, peer_port=50376, proto="ssh",
                                              details_json={"ssh_software": "dropbear_2022.83"})], scope="private")
        self.assertEqual((embedded["device_type"], embedded["device_product"]), ("Router", "dropbear"))


class NetworkRoleTests(unittest.TestCase):
    def test_the_gateway_is_a_router_from_what_it_does(self):
        profile = infer_device_profile(
            [
                _row(local_port=67, peer_port=68, proto="dhcp", details_json={"dhcp_msg_type": "OFFER"}),
                _row(local_port=53, peer_port=51000, proto="dns", details_json={"dns_kind": "response"}),
            ],
            scope="private",
        )
        self.assertEqual(profile["device_type"], "Router")
        self.assertEqual(profile["device_confidence"], "high")
        self.assertIn("DHCP server (67)", profile["device_evidence"])
        self.assertIn("answers DNS (53)", profile["device_evidence"])

    def test_answering_dns_alone_is_only_a_hint_that_a_lan_host_is_the_gateway(self):
        profile = infer_device_profile(
            [_row(local_port=53, peer_port=51000, proto="dns", details_json={"dns_kind": "response"})], scope="private"
        )
        self.assertEqual(profile["device_type"], "Router")
        self.assertEqual(profile["device_confidence"], "low", "a resolver on the LAN is not necessarily the router")

    def test_a_public_resolver_is_a_server_not_a_router(self):
        profile = infer_device_profile(
            [_row(local_port=53, peer_port=51000, proto="dns", details_json={"dns_kind": "response"})], scope="public"
        )
        self.assertEqual(profile["device_type"], "Server")

    def test_the_machine_asking_the_questions_is_not_the_resolver(self):
        profile = infer_device_profile(
            [_row(local_port=51000, peer_port=53, proto="dns", details_json={"dns_kind": "query"})], scope="private"
        )
        self.assertEqual(profile["device_type"], "Unknown")

    def test_a_tls_server_on_443_is_a_server(self):
        profile = infer_device_profile(
            [_row(local_port=443, peer_port=51000, proto="tls", details_json={"tls_handshake": "ServerHello"})],
            scope="public",
        )
        self.assertEqual(profile["device_type"], "Server")

    def test_lldp_and_upnp_descriptions(self):
        switch = infer_device_profile([_row(proto="lldp", details_json={
            "lldp_system_name": "core-sw1", "lldp_system_description": "Cisco IOS Software, Catalyst L3 Switch"})], scope="private")
        self.assertEqual(switch["device_type"], "Switch")
        gateway = infer_device_profile([_row(local_port=1900, peer_port=1900, proto="ssdp", details_json={
            "ssdp_method": "NOTIFY", "ssdp_target": "urn:schemas-upnp-org:device:InternetGatewayDevice:1"})], scope="private")
        self.assertEqual(gateway["device_type"], "Router")


class LocalNetworkFactsTests(unittest.TestCase):
    """TTL and the hardware address only describe a host that is on the local network."""

    def test_an_initial_ttl_of_128_on_the_lan_means_windows(self):
        for ttl in (128, 120, 65):
            with self.subTest(ttl=ttl):
                profile = infer_device_profile([_row(proto="udp", ttl=ttl)], scope="private")
                self.assertEqual((profile["device_type"], profile["device_product"]), ("PC", "windows"))

    def test_other_initial_ttls_say_nothing(self):
        for ttl in (64, 255, 52):
            with self.subTest(ttl=ttl):
                self.assertEqual(infer_device_profile([_row(proto="udp", ttl=ttl)], scope="private")["device_type"], "Unknown")

    def test_ttl_and_hardware_address_do_not_apply_to_a_host_beyond_the_lan(self):
        observations = [_row(proto="udp", ttl=118, eth="6a:e9:d9:eb:b8:59")]
        self.assertEqual(infer_device_profile(observations, scope="public")["device_type"], "Unknown")
        self.assertNotEqual(infer_device_profile(observations, scope="private")["device_type"], "Unknown")

    def test_a_randomized_hardware_address_suggests_a_phone_with_low_confidence(self):
        profile = infer_device_profile([_row(proto="arp", eth="2e:81:71:1f:e7:fa")], scope="private")
        self.assertEqual(profile["device_type"], "Phone")
        self.assertEqual(profile["device_confidence"], "low")
        self.assertEqual(profile["device_evidence"], ["randomized MAC address"])

    def test_an_ordinary_or_virtual_hardware_address_is_not_a_privacy_address(self):
        for mac in ("8c:e9:ee:b6:90:c7", "02:42:ac:11:00:02", "52:54:00:12:34:56", "ff:ff:ff:ff:ff:ff", "33:33:00:00:00:fb"):
            with self.subTest(mac=mac):
                self.assertEqual(infer_device_profile([_row(proto="arp", eth=mac)], scope="private")["device_type"], "Unknown")

    def test_a_public_host_needs_strong_evidence_to_be_anything_but_a_server(self):
        weak = [_row(proto="tcp", banner_text="android desktop iphone")]
        self.assertEqual(infer_device_profile(weak, scope="public")["device_type"], "Unknown")
        strong = [_client("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130")]
        self.assertEqual(infer_device_profile(strong, scope="public")["device_type"], "PC")


class DeviceCatalogTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(Path(self._tmp.name) / "devices.db")
        self.addCleanup(self.store.close)

    def _packet(self, **fields):
        base = {"interface": "eth0", "length": 80, "proto": "tcp"}
        base.update(fields)
        return self.store.register_packet(base)

    def _catalog(self):
        return {row["ip"]: row for row in self.store.list_ip_catalog(limit=50)}

    def test_ip_catalog_is_enriched_with_device_profile(self):
        self._packet(src_ip="192.168.1.20", dst_ip="192.168.1.40", src_port=52331, dst_port=9100, banner_text="HP LaserJet")
        rows = self._catalog()
        self.assertEqual(rows["192.168.1.40"]["device_type"], "Printer")
        self.assertIn("device_evidence", rows["192.168.1.40"])
        self.assertIn("device_product", rows["192.168.1.40"])

    def test_a_web_conversation_is_classified_for_each_end_by_what_that_end_sent(self):
        client, server = "192.168.1.20", "203.0.113.80"
        self._packet(src_ip=client, dst_ip=server, src_port=48650, dst_port=80, proto="http",
                     summary="HTTP GET / HTTP/1.1", http_user_agent="Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0")
        self._packet(src_ip=server, dst_ip=client, src_port=80, dst_port=48650, proto="http",
                     summary="HTTP response HTTP/1.1 200 OK", http_server="nginx/1.24.0", http_status="200")
        # A body chunk full of JavaScript from the same server, the way a real page arrives.
        self._packet(src_ip=server, dst_ip=client, src_port=80, dst_port=48650, proto="http",
                     summary="switch(a.which){case 1: router printer}", banner_text="switch router printer camera")
        rows = self._catalog()

        self.assertEqual(rows[server]["device_type"], "Server")
        self.assertEqual(rows[server]["device_product"], "nginx")
        self.assertEqual(rows[server]["device_product_version"], "1.24.0")
        self.assertEqual(rows[client]["device_type"], "PC")
        self.assertEqual(rows[client]["device_product"], "linux")
        self.assertNotEqual(rows[client]["device_product"], "nginx")

    def test_a_chatty_protocol_does_not_crowd_out_the_one_that_identifies_the_host(self):
        # Many more DNS lookups than anything else, all more recent than the one HTTP
        # request. Sampling the newest rows would never have seen its User-Agent.
        host = "192.168.1.20"
        self._packet(src_ip=host, dst_ip="203.0.113.80", src_port=48650, dst_port=80, proto="http",
                     summary="HTTP GET / HTTP/1.1", http_user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130")
        for index in range(80):
            self._packet(src_ip=host, dst_ip="192.168.1.1", src_port=40000 + index, dst_port=53, proto="dns",
                         summary=f"DNS query host{index}.example", details_json=json.dumps({"dns_kind": "query", "dns_qtype": "A"}))
        self.assertEqual(self._catalog()[host]["device_type"], "PC")

    def test_broadcast_and_unspecified_addresses_are_not_devices(self):
        self._packet(src_ip="0.0.0.0", dst_ip="255.255.255.255", src_port=68, dst_port=67, proto="dhcp",
                     summary="DHCP DISCOVER", details_json=json.dumps({"dhcp_msg_type": "DISCOVER"}))
        rows = self._catalog()
        self.assertEqual(rows["255.255.255.255"]["device_type"], "Unknown")
        self.assertEqual(rows["0.0.0.0"]["device_type"], "Unknown")


if __name__ == "__main__":
    unittest.main()
