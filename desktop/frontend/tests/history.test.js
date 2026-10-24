import assert from "node:assert/strict";
import test from "node:test";
import {
  ARP_EVENT_KINDS,
  arpEventColor,
  arpEventHelp,
  arpEventLabel,
  arpEventSummary,
  dnsRcodeColor,
  dnsSourceLabel,
  dnsTypeColor,
  formatTtlRange,
  isIpAddress,
  macVendorHint,
  macVendorLabel,
} from "../src/utils/history.js";
import { NAV_LINKS, navDestinations } from "../src/utils/navigation.js";
import router from "../src/router/index.js";

test("addresses are told apart from names", () => {
  for (const ip of ["93.184.216.34", "0.0.0.0", "255.255.255.255", "2606:2800:220:1::1", "::1", "fe80::1%eth0"]) {
    assert.ok(isIpAddress(ip), ip);
  }
  for (const name of ["", "example.com", "cdn.example.net", "999.1.1.1", "1.2.3", "a:b", null, undefined]) {
    assert.ok(!isIpAddress(name), String(name));
  }
});

test("record types that carry arbitrary data stand out", () => {
  assert.equal(dnsTypeColor("A"), "info");
  assert.equal(dnsTypeColor("aaaa"), "info");
  assert.equal(dnsTypeColor("TXT"), "warning");
  assert.equal(dnsTypeColor("ANY"), "error");
  assert.equal(dnsTypeColor("CNAME"), "secondary");
  assert.equal(dnsTypeColor("WEIRD"), "default");
});

test("response codes: a name that does not exist is a warning, a broken resolver an error", () => {
  assert.equal(dnsRcodeColor("NOERROR"), "success");
  assert.equal(dnsRcodeColor("NXDOMAIN"), "warning");
  assert.equal(dnsRcodeColor("SERVFAIL"), "error");
  assert.equal(dnsRcodeColor("REFUSED"), "error");
  assert.equal(dnsRcodeColor(""), "default");
});

test("sources are named the way people write them", () => {
  assert.equal(dnsSourceLabel("dns"), "DNS");
  assert.equal(dnsSourceLabel("mdns"), "mDNS");
  assert.equal(dnsSourceLabel("llmnr"), "LLMNR");
  assert.equal(dnsSourceLabel(""), "DNS");
  assert.equal(dnsSourceLabel("nbns"), "NBNS");
});

test("a TTL shows as a value, a range, or nothing", () => {
  assert.equal(formatTtlRange(300, 300), "300 s");
  assert.equal(formatTtlRange(20, 300), "20–300 s");
  assert.equal(formatTtlRange(null, null), "-");
  assert.equal(formatTtlRange(undefined, undefined), "-");
  assert.equal(formatTtlRange(0, 0), "0 s", "a zero TTL is a real value");
  assert.equal(formatTtlRange(60, null), "60 s");
});

test("MAC manufacturers and private-address states have useful labels", () => {
  const assigned = {
    mac_vendor: "Apple, Inc.",
    mac_vendor_registry: "MA-L",
    mac_vendor_prefix: "F0EE7A",
    mac_vendor_prefix_bits: 24,
    mac_address_kind: "global",
  };
  assert.equal(macVendorLabel(assigned), "Apple, Inc.");
  assert.equal(macVendorHint(assigned), "MA-L · F0EE7A / 24 bits · IEEE Registration Authority");
  assert.equal(macVendorLabel({ mac_address_kind: "local" }), "Local / aleatoria");
  assert.equal(macVendorLabel({ mac_address_kind: "multicast" }), "Multicast");
  assert.equal(macVendorLabel({ mac_address_kind: "unknown" }), "Fabricante desconocido");
});

test("every kind of ARP change is described", () => {
  assert.deepEqual([...ARP_EVENT_KINDS].sort(), ["ip_mac_changed", "mac_mismatch", "mac_new_ip", "new_device"]);
  for (const kind of ARP_EVENT_KINDS) {
    assert.ok(arpEventLabel(kind) && arpEventLabel(kind) !== kind, kind);
    assert.ok(arpEventHelp(kind).length > 20, kind);
    assert.notEqual(arpEventColor(kind), "default", kind);
  }
  assert.equal(arpEventColor("ip_mac_changed"), "error", "the spoofing signature is the loudest");
  assert.equal(arpEventLabel("unheard-of"), "unheard-of");
  assert.equal(arpEventColor("unheard-of"), "default");
});

test("the summary says what moved from where to where", () => {
  assert.equal(
    arpEventSummary({ kind: "ip_mac_changed", ip: "192.168.1.1", mac: "aa:bb:cc:00:00:99", previous_mac: "aa:bb:cc:00:00:01" }),
    "192.168.1.1: aa:bb:cc:00:00:01 → aa:bb:cc:00:00:99",
  );
  assert.equal(
    arpEventSummary({ kind: "mac_new_ip", ip: "192.168.1.77", mac: "aa:bb:cc:dd:ee:20", previous_ip: "192.168.1.20" }),
    "aa:bb:cc:dd:ee:20: 192.168.1.20 → 192.168.1.77",
  );
  assert.equal(arpEventSummary({ kind: "new_device", ip: "10.0.0.2", mac: "aa:bb:cc:dd:ee:02" }), "aa:bb:cc:dd:ee:02 (10.0.0.2)");
  assert.equal(arpEventSummary({ kind: "mac_mismatch", ip: "10.0.0.2", mac: "m", detail: "a announces b" }), "a announces b");
  assert.equal(arpEventSummary(null), "undefined (undefined)");
});

test("ARP and DNS have independent sidebar and command-palette destinations", () => {
  for (const name of ["ARP", "DNS"]) {
    const path = `/${name.toLowerCase()}`;
    const link = NAV_LINKS.find((item) => item.label === name);
    assert.equal(link?.to, path);
    assert.equal(link.children, undefined, "one click opens the protocol view");
    const destination = navDestinations().find((item) => item.to === path);
    assert.equal(destination?.label, name);
    assert.equal(destination.parent, undefined);
    const route = router.resolve(path);
    assert.equal(route.name, name.toLowerCase());
    assert.ok(route.matched.at(-1).components.default);
  }
  assert.notEqual(router.resolve("/arp").matched.at(-1).components.default, router.resolve("/dns").matched.at(-1).components.default);
});

test("old history links and route names redirect to the independent views", () => {
  for (const protocol of ["dns", "arp"]) {
    const route = router.resolve(`/history/${protocol}`);
    assert.equal(route.matched.at(-1).redirect, `/${protocol}`);
    assert.equal(router.resolve({ name: `history-${protocol}` }).matched.at(-1).redirect, `/${protocol}`);
  }
  assert.equal(router.resolve("/history").matched.at(-1).redirect, "/dns");
});
