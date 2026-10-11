// How the DNS and ARP history views present what the server recorded. Kept out
// of the components so the wording and the colours can be checked on their own.

const IPV4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9a-f:]+(?:%\w+)?$/i;

export function isIpAddress(value) {
  const text = String(value || "").trim();
  if (!text) return false;
  if (IPV4.test(text)) return true;
  // An IPv6 address has at least two colons; "a:b" is only hex letters.
  return text.split(":").length >= 3 && IPV6.test(text);
}

// Record types worth a second look get a warm colour: TXT and NULL carry
// arbitrary data (the usual tunnelling and exfiltration channel), ANY is the
// amplification query.
export function dnsTypeColor(type) {
  switch (String(type || "").toUpperCase()) {
    case "A":
    case "AAAA":
      return "info";
    case "CNAME":
    case "PTR":
      return "secondary";
    case "MX":
    case "NS":
    case "SOA":
    case "SRV":
    case "HTTPS":
      return "primary";
    case "TXT":
    case "NULL":
      return "warning";
    case "ANY":
      return "error";
    default:
      return "default";
  }
}

export function dnsRcodeColor(rcode) {
  switch (String(rcode || "").toUpperCase()) {
    case "NOERROR":
      return "success";
    case "NXDOMAIN":
      return "warning";
    case "":
      return "default";
    default:
      return "error";
  }
}

const SOURCE_LABELS = { dns: "DNS", mdns: "mDNS", llmnr: "LLMNR" };

export function dnsSourceLabel(source) {
  const key = String(source || "dns").toLowerCase();
  return SOURCE_LABELS[key] || key.toUpperCase();
}

// "300 s" when the TTL never moved, "20-300 s" when it did, "-" when no
// record carried one (a question, or a response without answers).
export function formatTtlRange(min, max) {
  const low = Number.isFinite(Number(min)) && min !== null && min !== "" ? Number(min) : null;
  const high = Number.isFinite(Number(max)) && max !== null && max !== "" ? Number(max) : null;
  if (low === null && high === null) return "-";
  if (low === null || high === null || low === high) return `${low ?? high} s`;
  return `${low}–${high} s`;
}

const ARP_EVENTS = {
  new_device: {
    label: "Dispositivo nuevo",
    color: "info",
    help: "Una dirección MAC que no se había visto antes apareció en la red.",
  },
  mac_new_ip: {
    label: "Nueva IP",
    color: "secondary",
    help: "Un dispositivo conocido empezó a usar otra dirección IP (DHCP, o un segundo adaptador).",
  },
  ip_mac_changed: {
    label: "IP cambió de MAC",
    color: "error",
    help: "Una dirección IP que pertenecía a una MAC ahora la reclama otra. Es lo que hace un ataque de suplantación ARP, pero también un equipo reemplazado.",
  },
  mac_mismatch: {
    label: "MAC no coincide",
    color: "warning",
    help: "La MAC del encabezado Ethernet no es la que el paquete ARP dice tener. Lo hacen los atacantes y también los proxies ARP.",
  },
};

export const ARP_EVENT_KINDS = Object.keys(ARP_EVENTS);

export function arpEventLabel(kind) {
  return (ARP_EVENTS[kind] || {}).label || String(kind || "-");
}

export function arpEventColor(kind) {
  return (ARP_EVENTS[kind] || {}).color || "default";
}

export function arpEventHelp(kind) {
  return (ARP_EVENTS[kind] || {}).help || "";
}

// What changed, in one line, for the events table.
export function arpEventSummary(event) {
  const item = event || {};
  if (item.kind === "ip_mac_changed") return `${item.ip}: ${item.previous_mac || "?"} → ${item.mac}`;
  if (item.kind === "mac_new_ip") return `${item.mac}: ${item.previous_ip || "?"} → ${item.ip}`;
  if (item.kind === "new_device") return `${item.mac} (${item.ip})`;
  return item.detail || `${item.mac} (${item.ip})`;
}
