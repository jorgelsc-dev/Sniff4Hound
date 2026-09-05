import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sniff4hound.ai_learning import features, fingerprint, forward, initial_model, train, update_feedback, learning_snapshot
from sniff4hound.packet_ai import analyze_packets
from sniff4hound.store import SniffStore
from tests.test_packet_ai import packet


class LearningTests(unittest.TestCase):
    def test_features_and_real_forward_values_are_bounded(self):
        x = features(bytes(range(256)) * 4)
        self.assertEqual(len(x), 8)
        self.assertTrue(all(0 <= v <= 1 and math.isfinite(v) for v in x))
        hidden, output = forward(initial_model(), x)
        self.assertEqual(len(hidden), 6)
        self.assertTrue(0 < output < 1)
        self.assertAlmostEqual(x[2], 1)

    def test_backpropagation_learns_both_classes(self):
        examples = [dict(features=[0.0] * 8, label='benign', confidence=3),
                    dict(features=[1.0] * 8, label='malicious', confidence=3)]
        model, history = train(examples)
        self.assertLess(history[-1]['loss'], history[0]['loss'])
        self.assertLess(forward(model, examples[0]['features'])[1], 0.3)
        self.assertGreater(forward(model, examples[1]['features'])[1], 0.7)

    def test_feedback_is_idempotent_correctable_and_retractable(self):
        p = packet()
        first = update_feedback({}, p, 'malicious', 3, 'evidence')
        again = update_feedback(first, p, 'malicious', 3, 'evidence')
        self.assertEqual(first, again)
        corrected = update_feedback(first, p, 'benign', 1, 'corrected')
        self.assertEqual(len(corrected['examples']), 1)
        self.assertEqual(corrected['revision'], 2)
        self.assertEqual(corrected['audit'][-1]['previous'], 'malicious')
        self.assertEqual(corrected['model'], update_feedback({}, p, 'benign', 1, 'corrected')['model'])
        removed = update_feedback(corrected, p, 'unreviewed', 1, '')
        self.assertEqual(removed['examples'], [])
        self.assertEqual(removed['model'], initial_model())

    def test_duplicate_frames_do_not_multiply_reward(self):
        state = update_feedback({}, packet(1), 'benign', 1, '')
        state = update_feedback(state, packet(2), 'benign', 1, '')
        self.assertEqual(len(state['examples']), 1)
        self.assertEqual(state['revision'], 1)

    def test_confidence_weights_the_learning_signal(self):
        low, _ = train([dict(features=[1.0] * 8, label='malicious', confidence=1)])
        high, _ = train([dict(features=[1.0] * 8, label='malicious', confidence=3)])
        self.assertGreater(forward(high, [1.0] * 8)[1], forward(low, [1.0] * 8)[1])

    def test_replay_capacity_evicts_oldest_example(self):
        examples = [dict(key=str(i), features=[0.0] * 8, label='benign', confidence=1, note='') for i in range(200)]
        with patch('sniff4hound.ai_learning.train', return_value=(initial_model(), [])):
            state = update_feedback({'examples': examples}, packet(), 'malicious', 1, '')
        self.assertEqual(len(state['examples']), 200)
        self.assertEqual(state['examples'][0]['key'], '1')
        self.assertEqual(state['examples'][-1]['key'], fingerprint(packet()))

    def test_warmup_does_not_present_untrained_score(self):
        rows = [packet()]
        snapshot = learning_snapshot({}, rows, analyze_packets(rows))
        self.assertFalse(snapshot['learning']['ready'])
        self.assertIsNone(snapshot['rows'][0]['neural_score'])
        self.assertIsNotNone(snapshot['rows'][0]['activations']['output'])

    def test_both_classes_required_and_ready_predictions_match_graph(self):
        rows = [packet(i + 1, bytes([i]) * 256) for i in range(6)]
        state = {}
        for i, p in enumerate(rows):
            state = update_feedback(state, p, 'benign' if i < 3 else 'malicious', 2, '')
        snapshot = learning_snapshot(state, rows, analyze_packets(rows))
        self.assertTrue(snapshot['learning']['ready'])
        self.assertEqual(snapshot['candidates'], 0)  # all reviewed
        for row in snapshot['rows']:
            self.assertEqual(row['neural_score'], round(row['activations']['output'] * 100, 1))


class LearningApiTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / 'ai.db'
        self.store = SniffStore(self.path)
        self.addCleanup(self.store.close)
        self.row = self.store.register_packet(packet())

    def test_feedback_persists_across_store_restart(self):
        self.store.save_ai_feedback(self.row['id'], 'malicious', 3, 'investigated')
        state = self.store.ai_learning_state()
        self.store.close()
        self.store = SniffStore(self.path)
        self.addCleanup(self.store.close)
        self.assertEqual(self.store.ai_learning_state(), state)

    def test_api_validation_auth_and_realtime_snapshot(self):
        from wsbuilder import Request
        from sniff4hound import app, auth
        def request(body, path='/api/ai/feedback'):
            return Request('POST', path, '', {}, json.dumps(body).encode(), ('203.0.113.34', 1234))
        valid = dict(packet_id=self.row['id'], label='malicious', confidence=3, note='test')
        with patch.object(app, 'store', self.store):
            for override in ({'label': 'maybe'}, {'confidence': True}, {'confidence': 4}, {'packet_id': True}, {'note': 'x' * 501}):
                with self.subTest(override=override), self.assertRaises(ValueError):
                    app.ai_feedback(request(valid | override))
            with patch.object(app, 'REQUIRE_AUTH', True), patch.object(auth, 'REQUIRE_AUTH', True), patch.object(app, 'RATE_LIMITER', auth.AuthRateLimiter()):
                self.assertEqual(app.app.dispatch(request(valid)).status, 401)
                self.assertEqual(self.store.ai_learning_state(), {})
            app.ai_feedback(request(valid))
            params = app._normalize_feed_params(Request('GET', '/ws/ai', 'threshold=73', {}, b'', ('127.0.0.1', 1)))
            snapshot = app._feed_payload('ai', params)
            self.assertEqual(snapshot['data']['threshold'], 73)
            self.assertEqual(snapshot['data']['learning']['revision'], 1)
            self.assertEqual(snapshot['data']['learning']['total'], 1)
            with self.assertRaises(ValueError):
                app.ai_feedback(request(valid | {'packet_id': 999999}))
