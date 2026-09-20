import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from sniff4hound.store import SniffStore

from sniff4hound.ai_learning import suggest_architecture


class SearchProgressTests(unittest.TestCase):
    def test_waiting_for_both_classes_does_not_claim_a_search_completed(self):
        report = {}
        with patch('sniff4hound.ai_learning.train') as train:
            result = suggest_architecture({'examples': [], 'revision': 4}, [6], report=report)
        train.assert_not_called()
        self.assertIsNone(result)
        self.assertEqual(report['status'], 'waiting_labels')
        self.assertEqual(report['candidates'], [])
        self.assertEqual(report['revision'], 4)

    def test_report_contains_measured_candidates_even_without_improvement(self):
        state = {'examples': [{'label': label} for label in ['benign'] * 3 + ['malicious'] * 3], 'revision': 10}
        report = {}
        with patch('sniff4hound.ai_learning.train', return_value=({}, [])), \
             patch('sniff4hound.ai_learning._accuracy_for', return_value=0.8), \
             patch('sniff4hound.ai_learning._hidden_size_candidates', return_value=[[3], [9]]):
            result = suggest_architecture(state, [6], dismissed=[[9]], report=report)
        self.assertIsNone(result)
        self.assertEqual(report['status'], 'complete')
        self.assertEqual(report['current_accuracy'], 0.8)
        self.assertEqual(report['candidates'], [{'hidden_sizes': [3], 'accuracy': 0.8}])

    def test_winning_candidate_is_returned_and_recorded(self):
        state = {'examples': [{'label': label} for label in ['benign'] * 3 + ['malicious'] * 3]}
        report = {}
        with patch('sniff4hound.ai_learning.train', return_value=({}, [])), \
             patch('sniff4hound.ai_learning._accuracy_for', side_effect=[0.5, 0.9]), \
             patch('sniff4hound.ai_learning._hidden_size_candidates', return_value=[[9]]):
            result = suggest_architecture(state, [6], report=report)
        self.assertEqual(result['hidden_sizes'], [9])
        self.assertEqual(report['candidates'][0]['accuracy'], 0.9)

    def test_search_continues_when_retained_example_count_stops_growing(self):
        store = MagicMock()
        store._ai_learning_suggestion_raw.return_value = {
            'architecture': None, 'cohort': {'min_cohort': 10},
            'dismissed_architectures': [], 'checked_at_examples': 200,
            'checked_at_revision': 250,
        }
        store.get_ai_learning_config.return_value = {'hidden_sizes': [6]}
        state = {'revision': 255, 'examples': [{}] * 200}
        with patch('sniff4hound.ai_learning.suggest_architecture', return_value=None) as search:
            SniffStore._refresh_ai_learning_suggestion(store, state)
        search.assert_called_once()
        store.set_runtime_config.assert_called_once()

    def test_next_search_progress_uses_feedback_updates(self):
        store = MagicMock()
        store._ai_learning_suggestion_raw.return_value = {
            'architecture': None, 'cohort': None, 'checked_at_revision': 250,
        }
        store.ai_learning_state.return_value = {'revision': 253}
        result = SniffStore.get_ai_learning_suggestion(store)
        self.assertEqual(result['next_check'], {'completed': 3, 'required': 5})


class ArchitectureTournamentTests(unittest.TestCase):
    """store.start_ai_tournament()/_run_ai_tournament(): several candidate
    shapes train side by side each round (ai_learning.run_tournament_round,
    tested at the ai_learning.py level in tests/test_ai_learning.py); these
    tests cover the round-loop orchestration itself - round_tournament_round
    is patched throughout so each test controls exactly what every round
    "trains into" without waiting on real training."""

    def _store(self):
        tmp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp_dir, ignore_errors=True)
        store = SniffStore(Path(tmp_dir) / "test.db")
        self.addCleanup(store.close)
        return store

    def _seed_examples(self, store):
        examples = [{'label': 'benign'}] * 5 + [{'label': 'malicious'}] * 5
        state = {
            'revision': 1, 'examples': examples, 'model': {'layers': []}, 'history': [],
            'audit': [], 'training': {}, 'updated_at': '',
        }
        store.set_runtime_config("ai_learning_state", json.dumps(state))
        return examples

    def test_start_ai_tournament_requires_at_least_three_examples_per_class(self):
        store = self._store()
        with self.assertRaises(ValueError):
            store.start_ai_tournament()

    def test_start_ai_tournament_is_a_no_op_while_one_is_already_active(self):
        store = self._store()
        self._seed_examples(store)
        with store._ai_tournament_lock:
            store._ai_tournament['active'] = True
        with patch.object(store, '_run_ai_tournament') as run:
            store.start_ai_tournament()
        run.assert_not_called()

    def test_maybe_start_is_a_noop_when_training_is_disabled(self):
        store = self._store()
        self._seed_examples(store)
        store.set_runtime_config('training_enabled', '0')
        with patch.object(store, 'start_ai_tournament') as start:
            store.maybe_start_ai_tournament()
        start.assert_not_called()

    def test_maybe_start_launches_a_tournament_when_training_is_enabled(self):
        store = self._store()
        self._seed_examples(store)
        store.set_runtime_config('training_enabled', '1')
        with patch.object(store, '_run_ai_tournament') as run:
            store.maybe_start_ai_tournament()
        run.assert_called_once()
        self.assertTrue(store.get_ai_tournament_state()['active'])

    def test_maybe_start_swallows_not_enough_examples_yet(self):
        # Opportunistic auto-start (see save_ai_feedback()/ai_config()) -
        # too few labelled examples just means "try again next time", not an
        # error that should ever surface to the caller.
        store = self._store()
        store.set_runtime_config('training_enabled', '1')
        store.maybe_start_ai_tournament()  # must not raise
        self.assertFalse(store.get_ai_tournament_state()['active'])

    def test_tournament_keeps_running_until_training_is_disabled(self):
        # The tournament never stops on its own once it finds something good
        # - it only stops once training_enabled turns off (checked once per
        # round) or a manual stop is requested. get_training_enabled() is
        # patched to answer True for exactly 3 rounds, then False, so the
        # loop runs exactly 3 rounds before stopping on its own.
        store = self._store()
        examples = self._seed_examples(store)

        def fake_round(examples, shapes, progress=None, progress_lock=None):
            return [{'hidden_sizes': shape, 'accuracy': 0.5, 'parameters': {}} for shape in shapes]

        with patch('sniff4hound.ai_learning.run_tournament_round', side_effect=fake_round), \
             patch.object(store, 'get_training_enabled', side_effect=[True, True, True, False]):
            store._run_ai_tournament(examples, [6])

        state = store.get_ai_tournament_state()
        self.assertFalse(state['active'])
        self.assertEqual(state['stop_reason'], 'training_disabled')
        self.assertEqual(len(state['rounds_history']), 3)
        # The starting shape [6] is never itself a round-1 candidate (see
        # tournament_round_shapes), so the champion is necessarily a
        # different shape, and that difference should be queued as a
        # pending architecture suggestion through the normal accept/dismiss
        # flow.
        self.assertNotEqual(state['champion']['hidden_sizes'], [6])
        suggestion = store.get_ai_learning_suggestion()['architecture']
        self.assertIsNotNone(suggestion)
        self.assertEqual(suggestion['hidden_sizes'], state['champion']['hidden_sizes'])
        # The last round's candidates stay labelled champion/disqualified
        # for the UI rather than being cleared out from under it.
        statuses = {tuple(c['hidden_sizes']): c['status'] for c in state['candidates']}
        self.assertEqual(statuses[tuple(state['champion']['hidden_sizes'])], 'champion')
        self.assertEqual(list(statuses.values()).count('disqualified'), len(statuses) - 1)

    def test_manual_stop_before_any_round_leaves_no_suggestion(self):
        store = self._store()
        examples = self._seed_examples(store)
        with store._ai_tournament_lock:
            store._ai_tournament['stop_requested'] = True
        with patch('sniff4hound.ai_learning.run_tournament_round') as run_round:
            store._run_ai_tournament(examples, [6])
        run_round.assert_not_called()
        state = store.get_ai_tournament_state()
        self.assertEqual(state['stop_reason'], 'manual')
        self.assertEqual(state['rounds_history'], [])
        self.assertIsNone(store.get_ai_learning_suggestion()['architecture'])

    def test_champion_tracks_the_best_round_and_suggestion_reflects_it(self):
        # Round 1 always crowns some champion (nothing to compare against
        # yet, accuracy 0.5); round 2 is flat against it (no requeue); round
        # 3 genuinely improves (0.9) - the final suggestion should reflect
        # that better, later champion, not the first one found.
        store = self._store()
        examples = self._seed_examples(store)
        accuracies = iter([0.5, 0.5, 0.9])

        def fake_round(examples, shapes, progress=None, progress_lock=None):
            accuracy = next(accuracies)
            return [{'hidden_sizes': shape, 'accuracy': accuracy, 'parameters': {}} for shape in shapes]

        with patch('sniff4hound.ai_learning.run_tournament_round', side_effect=fake_round), \
             patch.object(store, 'get_training_enabled', side_effect=[True, True, True, False]):
            store._run_ai_tournament(examples, [6])

        state = store.get_ai_tournament_state()
        self.assertEqual(len(state['rounds_history']), 3)
        self.assertEqual(state['champion']['accuracy'], 0.9)
        suggestion = store.get_ai_learning_suggestion()['architecture']
        self.assertEqual(suggestion['suggested_accuracy'], 0.9)
        self.assertEqual(suggestion['hidden_sizes'], state['champion']['hidden_sizes'])
