import base64
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import MagicMock, patch

from sniff4hound.packet_ai import analyze_packets, image_png, packet_bytes
from sniff4hound.store import SniffStore
from sniff4hound.sniffer import Sniffer


def packet(index=1, data=b'\x00' * 128, **overrides):
    result = dict(id=index, raw_packet=data, proto='tcp', src_ip='8.8.8.8',
                  dst_ip='1.1.1.1', details_json='{"ai_detection_status":"evaluated"}')
    result.update(overrides)
    return result


class PacketImageTests(unittest.TestCase):
    def test_png_preserves_all_intensities_and_padding(self):
        data = bytes(range(256)) + b'\xff'
        url, height = image_png(data)
        png = base64.b64decode(url.split(',')[1])
        self.assertEqual(height, 5)
        self.assertEqual(struct.unpack('!II', png[16:24]), (64, 5))
        size = struct.unpack('!I', png[33:37])[0]
        scanlines = zlib.decompress(png[41:41 + size])
        pixels = b''.join(scanlines[i + 1:i + 65] for i in range(0, len(scanlines), 65))
        self.assertEqual(pixels[:257], data)
        self.assertEqual(pixels[257:], b'\0' * 63)

    def test_empty_and_partial_bytes(self):
        self.assertEqual(packet_bytes({'payload_hex': 'invalid'})[0], b'')
        self.assertEqual(packet_bytes({'payload_hex': '00ff'})[1:], ('payload_preview', True))
        self.assertEqual(len(packet_bytes(packet(data=b'X' * 5000))[0]), 4096)
        self.assertTrue(packet_bytes(packet(data=b'X' * 5000))[2])
        row = analyze_packets([packet(data=b'')])['rows'][0]
        self.assertIsNone(row['score'])
        self.assertIsNone(row['image'])

    def test_outlier_without_alert_is_candidate(self):
        rows = [packet(i) for i in range(20)] + [packet(99, b'\xff' * 128)]
        result = analyze_packets(rows)
        outlier = result['rows'][0]
        self.assertEqual(outlier['id'], 99)
        self.assertGreater(outlier['score'], 90)
        self.assertTrue(outlier['candidate'])
        self.assertEqual(result['candidates'], 1)
        self.assertTrue(all(row['score'] == 0 for row in result['rows'][1:]))

    def test_insufficient_protocol_cohort_has_no_score(self):
        rows = [packet(i) for i in range(19)] + [packet(99, proto='udp')]
        self.assertEqual(analyze_packets(rows)['analyzed'], 0)

    def test_alerted_muted_disabled_and_legacy_are_not_candidates(self):
        for extra in ({'tags_json': '[{"key":"monitor_id"}]'},
                      {'rule_hits_json': '[{"id":"rule"}]'},
                      {'details_json': '{}'},
                      {'details_json': '{"ai_detection_status":"muted"}'},
                      {'details_json': '{"ai_detection_status":"disabled"}'}):
            with self.subTest(extra=extra):
                rows = [packet(i) for i in range(20)] + [packet(99, b'\xff' * 128, **extra)]
                self.assertFalse(analyze_packets(rows)['rows'][0]['candidate'])


class AiStorageTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = SniffStore(Path(tmp.name) / 'test.db')
        self.addCleanup(self.store.close)

    def test_full_frame_survives_sql_serialization_and_metadata(self):
        self.store.register_packet(packet(data=bytes(range(256)) * 8, ai_sample=True, ai_detection_status='evaluated'))
        row = self.store.list_ai_packets()[0]
        self.assertEqual(len(packet_bytes(row)[0]), 2048)
        self.assertEqual(json.loads(row['details_json'])['ai_detection_status'], 'evaluated')
        self.assertTrue(analyze_packets([row])['rows'][0]['sampled'])

    def test_sampling_is_opt_in_rate_limited_and_does_not_fabricate_hits(self):
        sniffer = Sniffer(self.store, MagicMock())
        sniffer._ai_sampling_enabled = False
        with patch.object(sniffer, '_get_monitor_context', return_value=([], True)), \
             patch.object(sniffer, '_get_rulesets', return_value=[]), \
             patch.object(sniffer, '_is_own_dashboard_traffic', return_value=False), \
             patch.object(sniffer, '_detection_muted', return_value=False), \
             patch.object(sniffer, '_whitelisted', return_value=False), \
             patch('sniff4hound.sniffer.time.monotonic', return_value=100):
            sniffer._store_packet(packet())
            self.assertEqual(self.store.count_packets(), 0)
            sniffer._ai_sampling_enabled = True
            sniffer._store_packet(packet())
            sniffer._store_packet(packet())
        self.assertEqual(self.store.count_packets(), 1)
        row = self.store.list_ai_packets()[0]
        self.assertEqual(json.loads(row['rule_hits_json']), [])
        self.assertTrue(json.loads(row['details_json'])['ai_sample'])
        self.store.clear_detections(scope='all')
        self.assertEqual(self.store.list_ai_packets(), [])


class AiApiTests(unittest.TestCase):
    setUp = AiStorageTests.setUp

    def test_api_snapshot_config_validation_and_auth(self):
        from wsbuilder import Request
        from sniff4hound import app as module
        request = lambda method, path, body=b'': Request(method, path, '', {}, body, ('203.0.113.10', 1234))
        with patch.object(module, 'store', self.store):
            self.store.register_packet(packet())
            result = module.ai_packets(request('GET', '/api/ai/packets/'))
            self.assertEqual(len(result['rows']), 1)
            self.assertFalse(result['sampling_enabled'])
            result = module.ai_config(request('POST', '/api/ai/config', b'{"sampling_enabled":true}'))
            self.assertTrue(result['sampling_enabled'])
            self.assertEqual(self.store.get_runtime_config('ai_sampling_enabled'), '1')
            with self.assertRaises(ValueError):
                module.ai_config(request('POST', '/api/ai/config', b'{"sampling_enabled":"false"}'))
            with patch.object(module, 'REQUIRE_AUTH', True):
                for method, path in [('GET', '/api/ai/packets/'), ('POST', '/api/ai/config')]:
                    response = module.app.dispatch(request(method, path))
                    self.assertIn(response.status, (401, 429))
