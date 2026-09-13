import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sniff4hound.ai_learning import (
    ONLINE_BATCH_SIZE,
    export_model,
    features,
    fingerprint,
    forward,
    hidden_sizes_of,
    import_model,
    initial_model,
    is_current_model_shape,
    model_effectiveness,
    rebuild_for_hidden_sizes,
    train,
    update_feedback,
    learning_snapshot,
)
from sniff4hound.packet_ai import analyze_packets
from sniff4hound.store import SniffStore
from tests.test_packet_ai import packet


class LearningTests(unittest.TestCase):
    def test_features_and_real_forward_values_are_bounded(self):
        x = features(bytes(range(256)) * 4)
        self.assertEqual(len(x), 8)
        self.assertTrue(all(0 <= v <= 1 and math.isfinite(v) for v in x))
        hidden_layers, output = forward(initial_model(), x)
        self.assertEqual(len(hidden_layers), 1)
        self.assertEqual(len(hidden_layers[0]), 6)
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
        self.assertNotEqual(corrected['model'], first['model'])
        self.assertEqual(corrected['training']['mode'], 'online_mini_batch')
        removed = update_feedback(corrected, p, 'unreviewed', 1, '')
        self.assertEqual(removed['examples'], [])
        self.assertEqual(removed['model'], initial_model())

    def test_feedback_uses_bounded_online_batches_and_persisted_weights(self):
        state = {}
        with patch('sniff4hound.ai_learning.train', side_effect=AssertionError('full replay used')):
            for index in range(20):
                state = update_feedback(
                    state,
                    packet(index + 1, bytes([index + 1]) * 256),
                    'benign' if index % 2 else 'malicious',
                    2,
                    '',
                )
        self.assertEqual(state['training']['updates'], 20)
        self.assertLessEqual(state['training']['batch_size'], ONLINE_BATCH_SIZE)
        self.assertEqual(state['training']['samples_seen'], sum(min(i, ONLINE_BATCH_SIZE) for i in range(1, 21)))
        self.assertTrue(state['training']['weights_persisted'])

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

    def test_hidden_sizes_controls_the_configurable_neuron_count(self):
        model = initial_model(hidden_sizes=[4])
        self.assertEqual(hidden_sizes_of(model), [4])
        self.assertEqual(len(model['layers']), 2)  # 1 hidden + 1 output
        hidden_layers, output = forward(model, [0.5] * 8)
        self.assertEqual(len(hidden_layers), 1)
        self.assertEqual(len(hidden_layers[0]), 4)
        self.assertTrue(0 < output < 1)

    def test_multiple_hidden_layers_build_and_forward_correctly(self):
        model = initial_model(hidden_sizes=[8, 5, 3])
        self.assertEqual(hidden_sizes_of(model), [8, 5, 3])
        self.assertEqual(len(model['layers']), 4)  # 3 hidden + 1 output
        hidden_layers, output = forward(model, [0.5] * 8)
        self.assertEqual([len(layer) for layer in hidden_layers], [8, 5, 3])
        self.assertTrue(0 < output < 1)

    def test_train_respects_hidden_sizes(self):
        examples = [dict(features=[0.0] * 8, label='benign', confidence=3),
                    dict(features=[1.0] * 8, label='malicious', confidence=3)]
        model, _ = train(examples, hidden_sizes=[10, 4])
        self.assertEqual(hidden_sizes_of(model), [10, 4])

    def test_deep_network_still_learns_both_classes(self):
        examples = [dict(features=[0.0] * 8, label='benign', confidence=3),
                    dict(features=[1.0] * 8, label='malicious', confidence=3)]
        model, history = train(examples, hidden_sizes=[6, 4])
        self.assertLess(history[-1]['loss'], history[0]['loss'])
        self.assertLess(forward(model, examples[0]['features'])[1], 0.3)
        self.assertGreater(forward(model, examples[1]['features'])[1], 0.7)

    def test_feedback_retrains_from_scratch_when_hidden_sizes_change(self):
        # hidden_sizes configured after this state's model was last trained
        # leaves persisted weights shape-bound to the old shape - the next
        # feedback event has to notice and retrain, not silently keep
        # serving predictions from a stale architecture.
        state = update_feedback({}, packet(1), 'malicious', 2, '', hidden_sizes=[6])
        self.assertEqual(hidden_sizes_of(state['model']), [6])
        state = update_feedback(state, packet(2, bytes([9]) * 256), 'benign', 2, '', hidden_sizes=[4, 4])
        self.assertEqual(hidden_sizes_of(state['model']), [4, 4])
        self.assertEqual(len(state['examples']), 2)
        self.assertEqual(state['training']['mode'], 'full_retrain_on_config_change')

    def test_rebuild_for_hidden_sizes_keeps_examples_and_resizes(self):
        state = update_feedback({}, packet(), 'malicious', 3, '')
        rebuilt = rebuild_for_hidden_sizes(state, hidden_sizes=[8, 3])
        self.assertEqual(hidden_sizes_of(rebuilt['model']), [8, 3])
        self.assertEqual(rebuilt['examples'], state['examples'])
        self.assertEqual(rebuilt['revision'], state['revision'] + 1)

    def test_rebuild_for_hidden_sizes_with_no_examples_just_resets(self):
        rebuilt = rebuild_for_hidden_sizes({}, hidden_sizes=[5])
        self.assertEqual(rebuilt['model'], initial_model([5]))
        self.assertEqual(rebuilt['examples'], [])

    def test_is_current_model_shape_rejects_pre_multilayer_dicts(self):
        self.assertTrue(is_current_model_shape(initial_model()))
        self.assertFalse(is_current_model_shape(None))
        self.assertFalse(is_current_model_shape({}))
        self.assertFalse(is_current_model_shape({'w1': [], 'b1': [], 'w2': [], 'b2': 0.0}))
        self.assertFalse(is_current_model_shape({'layers': []}))

    def test_legacy_pre_multilayer_model_does_not_crash_read_paths(self):
        # Regression: a real install with AI feedback from before the
        # multi-layer rewrite has "model": {"w1":..,"b1":..,"w2":..,"b2":..}
        # persisted (no "layers" key at all) in its ai_learning_state -
        # every read path used to call model['layers'] unconditionally and
        # crashed the whole /api/ai/packets/ endpoint with KeyError('layers').
        legacy_state = {
            'revision': 3,
            'examples': [dict(key='k1', features=[0.0] * 8, label='benign', confidence=2, note='')],
            'model': {'w1': [[0.0] * 8] * 6, 'b1': [0.0] * 6, 'w2': [0.0] * 6, 'b2': 0.0},
            'history': [], 'audit': [], 'training': {},
        }
        self.assertEqual(model_effectiveness(legacy_state), {'ready': False, 'accuracy': None, 'correct': 0, 'total': 1})
        exported = export_model(legacy_state)
        self.assertEqual(exported['hidden_sizes'], [6])
        rows = [packet()]
        snapshot = learning_snapshot(legacy_state, rows, analyze_packets(rows))
        self.assertIsNotNone(snapshot['rows'][0]['activations']['output'])

    def test_legacy_model_triggers_a_full_retrain_on_the_next_feedback(self):
        legacy_state = {
            'revision': 1,
            'examples': [dict(key='k1', features=[0.0] * 8, label='benign', confidence=2, note='')],
            'model': {'w1': [[0.0] * 8] * 6, 'b1': [0.0] * 6, 'w2': [0.0] * 6, 'b2': 0.0},
            'history': [], 'audit': [], 'training': {},
        }
        state = update_feedback(legacy_state, packet(2, bytes([9]) * 256), 'malicious', 2, '')
        self.assertTrue(hidden_sizes_of(state['model']))  # doesn't crash, has the new shape
        self.assertEqual(state['training']['mode'], 'full_retrain_on_config_change')
        self.assertEqual(len(state['examples']), 2)  # the old example wasn't discarded

    def test_export_and_import_model_round_trips_architecture_and_weights(self):
        state = update_feedback({}, packet(1), 'malicious', 2, '', hidden_sizes=[7, 4])
        exported = export_model(state)
        self.assertEqual(exported['hidden_sizes'], [7, 4])
        self.assertEqual(exported['model'], state['model'])

        fresh_state, hidden_sizes = import_model({}, exported)
        self.assertEqual(hidden_sizes, [7, 4])
        self.assertEqual(fresh_state['model'], state['model'])
        self.assertEqual(fresh_state['training']['mode'], 'imported')

    def test_import_model_rejects_malformed_payloads(self):
        with self.assertRaises(ValueError):
            import_model({}, {})
        with self.assertRaises(ValueError):
            import_model({}, {'model': {'layers': []}})
        with self.assertRaises(ValueError):
            import_model({}, {'model': {'layers': [{'w': [[0.0] * 8], 'b': [0.0, 0.0]}]}})
        # Output layer must have exactly 1 neuron.
        bad_output = {'model': {'layers': [
            {'w': [[0.0] * 8] * 6, 'b': [0.0] * 6},
            {'w': [[0.0] * 6] * 2, 'b': [0.0] * 2},
        ]}}
        with self.assertRaises(ValueError):
            import_model({}, bad_output)

    def test_import_model_rejects_non_numeric_or_extreme_weights(self):
        valid = export_model({'model': initial_model([6])})
        bad_type = json.loads(json.dumps(valid))
        bad_type['model']['layers'][0]['w'][0][0] = 'nan'
        with self.assertRaises(ValueError):
            import_model({}, bad_type)

        bad_magnitude = json.loads(json.dumps(valid))
        bad_magnitude['model']['layers'][0]['b'][0] = 10_000_000
        with self.assertRaises(ValueError):
            import_model({}, bad_magnitude)

    def test_effectiveness_not_ready_without_both_classes(self):
        state = update_feedback({}, packet(1), 'malicious', 3, '')
        self.assertEqual(model_effectiveness(state), {'ready': False, 'accuracy': None, 'correct': 0, 'total': 1})

    def test_effectiveness_scores_agreement_with_operator_labels(self):
        # Perfectly separable examples: after training the model should
        # agree with every label it was trained from.
        examples = [dict(key=str(i), features=[0.0] * 8, label='benign', confidence=3, note='')
                    for i in range(3)]
        examples += [dict(key=str(i), features=[1.0] * 8, label='malicious', confidence=3, note='')
                     for i in range(3, 6)]
        model, _ = train(examples)
        state = {'examples': examples, 'model': model}
        result = model_effectiveness(state)
        self.assertTrue(result['ready'])
        self.assertEqual(result['total'], 6)
        self.assertEqual(result['correct'], 6)
        self.assertEqual(result['accuracy'], 1.0)

class LearningApiTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        forensic = patch('sniff4hound.store.STORE_RAW_PACKET_BYTES', True)
        forensic.start()
        self.addCleanup(forensic.stop)
        self.path = Path(tmp.name) / 'ai.db'
        self.store = SniffStore(self.path)
        self.addCleanup(self.store.close)
        self.row = self.store.register_packet(packet())

    def test_ai_learning_config_defaults_bounds_and_immediate_rebuild(self):
        from sniff4hound.ai_learning import hidden_sizes_of

        self.assertEqual(self.store.get_ai_learning_config(), {'hidden_sizes': [6], 'min_cohort': 20})
        self.store.save_ai_feedback(self.row['id'], 'malicious', 3, 'evidence')
        self.assertEqual(hidden_sizes_of(self.store.ai_learning_state()['model']), [6])

        with self.assertRaises(ValueError):
            self.store.set_ai_learning_config({'hidden_sizes': [2]})
        with self.assertRaises(ValueError):
            self.store.set_ai_learning_config({'hidden_sizes': []})
        with self.assertRaises(ValueError):
            self.store.set_ai_learning_config({'hidden_sizes': [6, 6, 6, 6, 6]})
        with self.assertRaises(ValueError):
            self.store.set_ai_learning_config({'min_cohort': 1000})

        updated = self.store.set_ai_learning_config({'hidden_sizes': [9, 5]})
        self.assertEqual(updated, {'hidden_sizes': [9, 5], 'min_cohort': 20})
        # Rebuilt immediately - not only on the next feedback event - so an
        # existing example's weights are never silently shape-mismatched.
        state = self.store.ai_learning_state()
        self.assertEqual(hidden_sizes_of(state['model']), [9, 5])
        self.assertEqual(len(state['examples']), 1)

    def test_export_and_import_ai_model_via_store(self):
        self.store.save_ai_feedback(self.row['id'], 'malicious', 3, 'evidence')
        exported = self.store.export_ai_model()
        self.assertEqual(exported['hidden_sizes'], [6])

        result = self.store.import_ai_model(exported)
        self.assertEqual(result['hidden_sizes'], [6])
        self.assertEqual(self.store.get_ai_learning_config()['hidden_sizes'], [6])

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
