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

test("the history views are reachable from the navigation and the router", () => {
  const history = NAV_LINKS.find((link) => link.label === "Historial");
  assert.ok(history, "a Historial entry");
  assert.deepEqual(history.children.map((child) => child.to), ["/history/dns", "/history/arp"]);
  const destinations = navDestinations().map((item) => item.to);
  assert.ok(destinations.includes("/history/dns") && destinations.includes("/history/arp"));
  const names = router.getRoutes().map((route) => route.path);
  for (const path of ["/history/dns", "/history/arp"]) assert.ok(names.includes(path), path);
  assert.equal(router.resolve("/history").redirectedFrom, undefined);
  assert.equal(router.resolve("/history").matched.at(-1).redirect, "/history/dns");
});
