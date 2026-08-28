from __future__ import annotations

import re
import unittest
from pathlib import Path

from sniff4hound.protocol_facets import PROTOCOL_FACETS
from sniff4hound.utils import KNOWN_PROTOCOLS

CATALOG = Path(__file__).resolve().parent.parent / "frontend" / "src" / "utils" / "protocolCatalog.js"

# [layer, icon, label, description] - the shape protocolCatalog.js declares.
ENTRY_RE = re.compile(r'^\s{2}"?([a-z0-9_-]+)"?:\s*\[\s*"([a-z]+)"', re.MULTILINE)
LAYER_RE = re.compile(r'\{\s*key:\s*"([a-z]+)"', re.MULTILINE)


def _catalog() -> dict[str, str]:
    return {name: layer for name, layer in ENTRY_RE.findall(CATALOG.read_text(encoding="utf-8"))}


def _declared_layers() -> set[str]:
    source = CATALOG.read_text(encoding="utf-8")
    block = source.split("export const LAYERS = [", 1)[1].split("];", 1)[0]
    return set(LAYER_RE.findall(block))


class CatalogCoverageTests(unittest.TestCase):
    """The UI catalog has to keep up with what the pipeline can emit."""

    def test_the_catalog_file_is_where_the_test_expects(self):
        self.assertTrue(CATALOG.exists(), f"{CATALOG} is missing")

    def test_every_protocol_the_pipeline_reports_has_a_card(self):
        # A protocol added to the backend and forgotten here renders with the
        # layer default and a generic label - which is how the Protocols view
        # ends up showing an unnamed chip nobody can act on.
        catalog = _catalog()
        missing = sorted(p for p in KNOWN_PROTOCOLS if p not in catalog)
        self.assertEqual(missing, [], f"protocols with no UI entry: {missing}")

    def test_the_catalog_does_not_invent_protocols(self):
        known = set(KNOWN_PROTOCOLS)
        extra = sorted(name for name in _catalog() if name not in known)
        self.assertEqual(extra, [], f"UI entries for protocols the pipeline never emits: {extra}")

    def test_every_entry_uses_a_declared_layer(self):
        layers = _declared_layers()
        wrong = {name: layer for name, layer in _catalog().items() if layer not in layers}
        self.assertEqual(wrong, {}, f"entries pointing at undeclared layers: {wrong}")

    def test_the_backend_and_the_ui_agree_on_the_protocol_set(self):
        self.assertEqual(
            sorted(_catalog()),
            sorted(p for p in KNOWN_PROTOCOLS if p in PROTOCOL_FACETS),
        )


class LayerClassificationTests(unittest.TestCase):
    def test_quic_is_a_transport(self):
        # QUIC is what HTTP/3 rides on; it replaces TCP rather than sitting on
        # it. It was filed under Application, which its own description
        # contradicts ("HTTP/3 transport over UDP").
        self.assertEqual(_catalog()["quic"], "transport")

    def test_the_tunnels_all_sit_at_the_same_layer(self):
        # They do the same job - carry another network's traffic inside this
        # one - and were split down the middle, half under Network and half
        # under Application, purely by which port they happen to use.
        catalog = _catalog()
        tunnels = ("gre", "esp", "ah", "ipip", "l2tp", "pptp", "openvpn", "wireguard", "vxlan", "geneve")
        layers = {name: catalog[name] for name in tunnels if name in catalog}
        self.assertEqual(
            set(layers.values()), {"network"},
            f"tunnels are spread across layers: {layers}",
        )

    def test_the_transport_layer_holds_what_applications_connect_on(self):
        catalog = _catalog()
        for name in ("tcp", "udp", "sctp", "dccp", "udplite", "quic"):
            self.assertEqual(catalog.get(name), "transport", f"{name} is not filed as a transport")

    def test_no_layer_is_left_empty(self):
        # An empty section renders as a heading with nothing under it.
        used = set(_catalog().values())
        for layer in _declared_layers():
            self.assertIn(layer, used, f"no protocol is filed under {layer!r}")


if __name__ == "__main__":
    unittest.main()
