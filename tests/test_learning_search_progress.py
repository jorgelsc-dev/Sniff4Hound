import unittest
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
