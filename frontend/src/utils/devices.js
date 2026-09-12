// Shared with IpsView's table and IpRelationshipGraph's node icons - the
// backend's infer_device_profile() (sniff4hound/store.py) is the source of
// the device_type vocabulary; this just maps that vocabulary to a
// presentation (icon + color), so it must stay in one place rather than
// duplicated per component.
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

export function deviceIcon(value) {
  return DEVICE_ICONS[value] || DEVICE_ICONS.Unknown;
}

export function deviceColor(value) {
  return DEVICE_COLORS[value] || DEVICE_COLORS.Unknown;
}
