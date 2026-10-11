// Shared with IpsView's table and IpRelationshipGraph's inspector - the
// backend's infer_device_profile() (sniff4hound/device_profiles.py) is the
// source of the device_type vocabulary and of the product it recognised
// (`device_product` id, `device_product_label`, `device_product_version`, e.g.
// nginx / Nginx / 1.18.0); this just maps those to a presentation (icon + color
// + the product's logo and name), so it must stay in one place rather than
// duplicated per component.
import { PRODUCT_LOGOS } from "./productLogos.js";

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

// Products whose logo is not in productLogos.js but that the MDI icon font
// ships a glyph for. A product with neither keeps its device type's generic
// icon and shows only its name: a made-up glyph would be worse than none.
const PRODUCT_MDI_ICONS = {
  windows: "mdi-microsoft-windows",
};

// Brand colours that are nearly black (Apple, Express, pfSense...) vanish on
// the dark theme, so they are replaced by a light neutral. 0.12 is the relative
// luminance that still gives the 3:1 contrast WCAG asks of a graphic against the
// theme's near-black surface (Apache's red passes it, Debian's dark red does not).
const LIGHT_NEUTRAL = "#E6EDF3";
const MIN_LOGO_LUMINANCE = 0.12;

function relativeLuminance(hex) {
  const channels = [0, 2, 4].map((offset) => {
    const value = parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

// The colour a brand logo is drawn in on the dark theme: its own, unless it
// would not be visible.
export function logoColor(hex) {
  const clean = String(hex || "").replace(/^#/, "");
  if (!/^[0-9a-fA-F]{6}$/.test(clean)) return LIGHT_NEUTRAL;
  return relativeLuminance(clean) < MIN_LOGO_LUMINANCE ? LIGHT_NEUTRAL : `#${clean.toUpperCase()}`;
}

// What to show for the product the backend recognised on a node, or null when
// it recognised none: {id, label, version, text, icon, iconColor}. `icon` is a
// Vuetify icon (an `svg:` path for a bundled brand logo) or null when there is
// no logo for it, in which case only `text` is shown.
export function productDisplay(node) {
  const id = String((node && node.device_product) || "");
  if (!id) return null;
  const label = String(node.device_product_label || id);
  const version = String(node.device_product_version || "");
  const logo = PRODUCT_LOGOS[id];
  const mdi = PRODUCT_MDI_ICONS[id];
  return {
    id,
    label,
    version,
    text: version ? `${label} ${version}` : label,
    icon: logo ? `svg:${logo.path}` : mdi || null,
    iconColor: logo ? logoColor(logo.hex) : undefined,
  };
}

// Evidence keyword -> a more specific icon than the device_type's generic
// one, and a display label. Kept for a runtime that predates the recognised
// product (`device_product`) and still reports only `metadata "nginx"` style
// evidence.
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
// `device_type` and, when the runtime recognised one, `device_product*`, returns
// everything needed to render it consistently - {icon, iconColor, color, label,
// detail, product}. `label` is always the coarse device_type (or "Unknown");
// `detail` is the product's name and version (or, for an older runtime, the
// software the evidence names), else null. `icon` is the product's logo when it
// has one, else the device type's icon; `iconColor` is set only for a logo.
export function deviceDisplay(node) {
  const type = (node && node.device_type) || "Unknown";
  const product = productDisplay(node);
  const legacy = product ? null : evidenceDetail(node && node.device_evidence);
  return {
    icon: (product && product.icon) || (legacy && legacy.icon) || deviceIcon(type),
    iconColor: product && product.icon ? product.iconColor : undefined,
    color: deviceColor(type),
    label: type,
    detail: product ? product.text : legacy ? legacy.label : null,
    product,
  };
}
