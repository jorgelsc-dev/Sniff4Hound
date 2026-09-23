// Shared with IpsView's table and IpRelationshipGraph's node icons - the
// backend's infer_device_profile() (sniff4hound/device_profiles.py) is the
// source of the device_type vocabulary and the device_evidence keyword
// hits behind it (e.g. `metadata "nginx"`, `metadata "android"`); this just
// maps that vocabulary to a presentation (icon + color + a more specific
// label when the evidence names actual software/an OS), so it must stay in
// one place rather than duplicated per component.
export const DEVICE_ICONS = {
  Router: "mdi-router-network",
  Switch: "mdi-access-point-network",
  Phone: "mdi-cellphone",
  PC: "mdi-monitor",
  Server: "mdi-server",
  Printer: "mdi-printer",
  Camera: "mdi-cctv",
  IoT: "mdi-devices",
  Unknown: "mdi-help-network-outline",
};

export const DEVICE_COLORS = {
  Router: "deep-purple",
  Switch: "indigo",
  Phone: "cyan",
  PC: "blue",
  Server: "green",
  Printer: "orange",
  Camera: "red",
  IoT: "teal",
  Unknown: "grey",
};

// Evidence keyword -> a more specific icon than the device_type's generic
// one, and a display label. Only names MDI actually ships an icon for get
// an icon override (a made-up "nginx" glyph would be worse than none); the
// rest just refine the label shown next to the generic device icon.
const EVIDENCE_DETAILS = {
  android: { label: "Android", icon: "mdi-android" },
  iphone: { label: "iPhone", icon: "mdi-apple" },
  ios: { label: "iOS", icon: "mdi-apple" },
  macbook: { label: "macOS", icon: "mdi-apple" },
  windows: { label: "Windows", icon: "mdi-microsoft-windows" },
  ubuntu: { label: "Ubuntu" },
  fedora: { label: "Fedora" },
  nginx: { label: "Nginx" },
  apache: { label: "Apache" },
  openssh: { label: "OpenSSH" },
  postgresql: { label: "PostgreSQL" },
  mysql: { label: "MySQL" },
  redis: { label: "Redis" },
  kubernetes: { label: "Kubernetes" },
  openwrt: { label: "OpenWrt" },
  mikrotik: { label: "MikroTik" },
  routeros: { label: "RouterOS" },
  "fritz!box": { label: "FRITZ!Box" },
  pfsense: { label: "pfSense" },
  hikvision: { label: "Hikvision" },
  dahua: { label: "Dahua" },
};

export function deviceIcon(value) {
  return DEVICE_ICONS[value] || DEVICE_ICONS.Unknown;
}

export function deviceColor(value) {
  return DEVICE_COLORS[value] || DEVICE_COLORS.Unknown;
}

// Pulls the first recognized software/OS keyword out of a node's
// device_evidence list (backend strings like `metadata "nginx"` or
// `DHCP server (67)`) - undefined when nothing in there is specific enough
// to name, which is the common case for e.g. a bare port-number hint.
function evidenceDetail(evidence) {
  if (!Array.isArray(evidence)) return null;
  for (const item of evidence) {
    const match = /metadata\s+\p{Quotation_Mark}([^"”]+)\p{Quotation_Mark}/u.exec(String(item || ""));
    const keyword = match ? match[1].toLowerCase() : "";
    if (keyword && EVIDENCE_DETAILS[keyword]) return EVIDENCE_DETAILS[keyword];
  }
  return null;
}

// The single function views should call: given a node (or table row) with
// `device_type` and `device_evidence`, returns everything needed to render
// it consistently - {icon, color, label, detail}. `label` is always the
// coarse device_type (or "Unknown"); `detail` is the specific software/OS
// name when the evidence names one, else null.
export function deviceDisplay(node) {
  const type = (node && node.device_type) || "Unknown";
  const detail = evidenceDetail(node && node.device_evidence);
  return {
    icon: (detail && detail.icon) || deviceIcon(type),
    color: deviceColor(type),
    label: type,
    detail: detail ? detail.label : null,
  };
}
