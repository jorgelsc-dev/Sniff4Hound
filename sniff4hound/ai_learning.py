"""Small inspectable supervised network trained only from operator labels.

Normal feedback uses a tiny online mini-batch and starts from the weights saved
by the previous update.  The full labelled set is never replayed for each click.
Training loss is not an estimate of production detection accuracy.
"""
import copy
import hashlib
import math
import random
from collections import Counter

from .packet_ai import packet_bytes
from .utils import utc_now

FEATURES = ['Intensidad media', 'Desviación', 'Entropía', 'Bytes cero',
            'Texto imprimible', 'Contraste horizontal', 'Contraste vertical', 'Ocupación']
MAX_EXAMPLES = 200
ONLINE_BATCH_SIZE = 8
ONLINE_EPOCHS = 8
ONLINE_LEARNING_RATE = 0.04
DEFAULT_HIDDEN_NEURONS = 6
MIN_HIDDEN_NEURONS = 3
MAX_HIDDEN_NEURONS = 16


def features(data):
    values = [v / 255 for v in data]
    mean = sum(values) / len(values)
    counts = Counter(data)
    entropy = -sum((n / len(data)) * math.log2(n / len(data)) for n in counts.values()) / 8
    horizontal = [abs(values[i] - values[i - 1]) for i in range(1, len(values)) if i % 64]
    vertical = [abs(values[i] - values[i - 64]) for i in range(64, len(values))]
    return [mean, math.sqrt(sum((v - mean) ** 2 for v in values) / len(values)), entropy,
            counts[0] / len(data), sum(32 <= v < 127 for v in data) / len(data),
            sum(horizontal) / max(1, len(horizontal)), sum(vertical) / max(1, len(vertical)), len(data) / 4096]


def fingerprint(packet):
    data, source, partial = packet_bytes(packet)
    return hashlib.sha256(str((packet.get('proto'), source, partial)).encode() + data).hexdigest()


def initial_model(hidden_size=DEFAULT_HIDDEN_NEURONS):
    rng = random.Random(41)
    return dict(w1=[[rng.uniform(-0.6, 0.6) for _ in FEATURES] for _ in range(hidden_size)],
                b1=[0.0] * hidden_size, w2=[rng.uniform(-0.6, 0.6) for _ in range(hidden_size)], b2=0.0)


def forward(model, x):
    # Hidden-layer size lives in the model itself (len(w1)/len(b1)/len(w2)),
    # not a constant here, so a persisted model keeps working regardless of
    # what DEFAULT_HIDDEN_NEURONS/the operator's configured size is right now.
    hidden = [math.tanh(sum(w * v for w, v in zip(weights, x)) + bias)
              for weights, bias in zip(model['w1'], model['b1'])]
    logit = sum(w * h for w, h in zip(model['w2'], hidden)) + model['b2']
    output = 1 / (1 + math.exp(-max(-30, min(30, logit))))
    return hidden, output


def train(examples, hidden_size=DEFAULT_HIDDEN_NEURONS):
    model = initial_model(hidden_size)
    history = []
    for epoch in range(80 if examples else 0):
        loss = 0.0
        for example in examples:
            x, y = example['features'], int(example['label'] == 'malicious')
            hidden, output = forward(model, x)
            loss -= y * math.log(max(output, 1e-12)) + (1 - y) * math.log(max(1 - output, 1e-12))
            delta = (output - y) * example['confidence'] / 3
            hidden_delta = [delta * w * (1 - h * h) for w, h in zip(model['w2'], hidden)]
            for j in range(hidden_size):
                model['w2'][j] -= 0.08 * delta * hidden[j]
                model['b1'][j] -= 0.08 * hidden_delta[j]
                for i in range(8):
                    model['w1'][j][i] -= 0.08 * hidden_delta[j] * x[i]
            model['b2'] -= 0.08 * delta
        if epoch % 10 == 0 or epoch == 79:
            history.append({'epoch': epoch + 1, 'loss': round(loss / len(examples), 6)})
    return model, history


def train_incremental(model, examples, *, epochs=ONLINE_EPOCHS, learning_rate=ONLINE_LEARNING_RATE, step=0,
                       hidden_size=DEFAULT_HIDDEN_NEURONS):
    """Update persisted weights with one small, bounded mini-batch.

    Keeping this separate from ``train`` preserves the deterministic full
    trainer for tests/diagnostics while production feedback stays O(1) as the
    saved example collection grows.
    """
    updated = copy.deepcopy(model) if model else initial_model(hidden_size)
    if not examples:
        return updated, []
    hidden_count = len(updated['w2'])
    loss = 0.0
    for _epoch in range(max(1, int(epochs))):
        loss = 0.0
        for example in examples:
            x, y = example['features'], int(example['label'] == 'malicious')
            hidden, output = forward(updated, x)
            loss -= y * math.log(max(output, 1e-12)) + (1 - y) * math.log(max(1 - output, 1e-12))
            delta = (output - y) * example['confidence'] / 3
            hidden_delta = [delta * w * (1 - h * h) for w, h in zip(updated['w2'], hidden)]
            for j in range(hidden_count):
                updated['w2'][j] -= learning_rate * delta * hidden[j]
                updated['b1'][j] -= learning_rate * hidden_delta[j]
                for i in range(8):
                    updated['w1'][j][i] -= learning_rate * hidden_delta[j] * x[i]
            updated['b2'] -= learning_rate * delta
    return updated, [{
        'epoch': int(step) + 1,
        'loss': round(loss / len(examples), 6),
        'batch_size': len(examples),
        'epochs': max(1, int(epochs)),
    }]


def rebuild_for_hidden_size(state, hidden_size=DEFAULT_HIDDEN_NEURONS):
    """Retrain from the retained examples under a new hidden-layer size.

    Persisted weights are shape-bound to whatever hidden_size they were last
    trained with - `forward()` would still run against a mismatched size
    without erroring (it infers shape from the model itself), but the
    resulting predictions would be meaningless carry-over from the old
    architecture. Called right when an operator changes the neuron count in
    Settings, rather than waiting for the next feedback event to notice."""
    examples = list(state.get('examples', []))
    revision = int(state.get('revision', 0)) + 1
    now = utc_now()
    if not examples:
        model = initial_model(hidden_size)
        entry = {'epoch': revision, 'loss': None, 'batch_size': 0, 'epochs': 0}
    else:
        model, full_history = train(examples, hidden_size=hidden_size)
        entry = dict(full_history[-1]) if full_history else {'loss': None}
        entry.update(epoch=revision, batch_size=len(examples))
    history = (list(state.get('history', [])) + [entry])[-30:]
    previous_training = state.get('training', {}) if isinstance(state.get('training'), dict) else {}
    training = {
        'mode': 'full_retrain_on_config_change',
        'updates': int(previous_training.get('updates', state.get('revision', 0))) + 1,
        'batch_size': len(examples),
        'batch_limit': ONLINE_BATCH_SIZE,
        'epochs_per_update': ONLINE_EPOCHS,
        'samples_seen': int(previous_training.get('samples_seen', 0)) + len(examples),
        'weights_persisted': True,
    }
    return dict(revision=revision, examples=examples, model=model, history=history,
                audit=state.get('audit', []), training=training, updated_at=now)


def model_effectiveness(state):
    """Resubstitution accuracy: how often the CURRENT persisted model's
    prediction agrees with the operator's own label, over the labelled
    examples it was trained from.

    This is not an estimate of real-world detection accuracy - see the
    module docstring on training loss - but it is the honest number
    available without asking the operator to hand-build a held-out labelled
    set the model never trained on."""
    examples = state.get('examples', [])
    counts = Counter(e['label'] for e in examples)
    ready = counts['benign'] >= 3 and counts['malicious'] >= 3
    if not ready or not examples:
        return {'ready': False, 'accuracy': None, 'correct': 0, 'total': len(examples)}
    model = state.get('model') or initial_model()
    correct = sum(
        1 for example in examples
        if ('malicious' if forward(model, example['features'])[1] >= 0.5 else 'benign') == example['label']
    )
    return {'ready': True, 'accuracy': round(correct / len(examples), 4), 'correct': correct, 'total': len(examples)}


def update_feedback(state, packet, label, confidence, note, *, hidden_size=DEFAULT_HIDDEN_NEURONS):
    data, _, _ = packet_bytes(packet)
    if not data:
        raise ValueError('El paquete no contiene bytes para aprender.')
    key = fingerprint(packet)
    examples = list(state.get('examples', []))
    previous = next((e for e in examples if e['key'] == key), None)
    if previous and (previous['label'], previous['confidence'], previous['note']) == (label, confidence, note):
        return state
    if label == 'unreviewed' and previous is None:
        return state
    examples = [e for e in examples if e['key'] != key]
    now = utc_now()
    changed_example = None
    if label != 'unreviewed':
        changed_example = dict(key=key, packet_id=packet['id'], proto=packet.get('proto'), features=features(data),
                               label=label, confidence=confidence, note=note, updated_at=now)
        examples.append(changed_example)
    examples = examples[-MAX_EXAMPLES:]
    revision = state.get('revision', 0) + 1
    previous_training = state.get('training', {}) if isinstance(state.get('training'), dict) else {}
    existing_model = state.get('model')
    # A hidden_size configured after this state's model was last (re)trained
    # leaves persisted weights shape-bound to the old size - forward() would
    # still run without erroring (it infers shape from the model itself) but
    # the predictions would be meaningless carry-over. Force a full retrain
    # here too, not just from rebuild_for_hidden_size(), in case a feedback
    # event races a config change.
    stale_architecture = bool(existing_model and len(existing_model.get('w1') or []) != hidden_size)
    if not examples:
        # With no remaining evidence there is nothing legitimate to retain.
        model = initial_model(hidden_size)
        new_history = [{'epoch': revision, 'loss': None, 'batch_size': 0, 'epochs': 0}]
        batch_size = 0
    elif stale_architecture:
        model, full_history = train(examples, hidden_size=hidden_size)
        entry = dict(full_history[-1]) if full_history else {'loss': None}
        entry.update(epoch=revision, batch_size=len(examples))
        new_history = [entry]
        batch_size = len(examples)
    elif changed_example is None:
        # Retraction removes the example from the replay buffer immediately.
        # Existing weights remain the accumulated online knowledge; future
        # small updates will move them without an expensive full rebuild.
        model = copy.deepcopy(existing_model or initial_model(hidden_size))
        new_history = [{'epoch': revision, 'loss': None, 'batch_size': 0, 'epochs': 0}]
        batch_size = 0
    else:
        # The corrected/new example is always in the batch, accompanied by a
        # few recent labels to reduce catastrophic forgetting.  Work stays
        # bounded even when the retained audit set reaches MAX_EXAMPLES.
        batch = examples[-ONLINE_BATCH_SIZE:]
        if all(example['key'] != key for example in batch):
            batch = [*batch[1:], changed_example]
        model, new_history = train_incremental(
            existing_model or initial_model(hidden_size), batch, step=revision - 1, hidden_size=hidden_size
        )
        batch_size = len(batch)
    history = (list(state.get('history', [])) + new_history)[-30:]
    audit = (state.get('audit', []) + [dict(packet_id=packet['id'], label=label, confidence=confidence,
             note=note, previous=previous['label'] if previous else None, revision=revision, at=now)])[-100:]
    training = {
        'mode': 'full_retrain_on_config_change' if stale_architecture else 'online_mini_batch',
        'updates': int(previous_training.get('updates', state.get('revision', 0))) + 1,
        'batch_size': batch_size,
        'batch_limit': ONLINE_BATCH_SIZE,
        'epochs_per_update': ONLINE_EPOCHS,
        'samples_seen': int(previous_training.get('samples_seen', 0)) + batch_size,
        'weights_persisted': True,
    }
    return dict(revision=revision, examples=examples, model=model, history=history, audit=audit,
                training=training, updated_at=now)


def learning_snapshot(state, packets, analysis, hidden_size=DEFAULT_HIDDEN_NEURONS):
    model = state.get('model') or initial_model(hidden_size)
    examples = state.get('examples', [])
    counts = Counter(e['label'] for e in examples)
    ready = counts['benign'] >= 3 and counts['malicious'] >= 3
    by_key = {e['key']: e for e in examples}
    by_id = {p['id']: p for p in packets}
    for row in analysis['rows']:
        packet = by_id[row['id']]
        data, _, _ = packet_bytes(packet)
        x = features(data) if data else None
        hidden, output = forward(model, x) if x else ([], None)
        reviewed = by_key.get(fingerprint(packet)) if data else None
        row.update(neural_score=round(output * 100, 1) if ready and output is not None else None,
                   activations={'input': x, 'hidden': hidden, 'output': output},
                   feedback={k: reviewed[k] for k in ('label', 'confidence', 'note')} if reviewed else None)
        scores = [v for v in (row['score'], row['neural_score']) if v is not None]
        row['priority_score'] = max(scores) if scores else None
        row['candidate'] = (row['priority_score'] or 0) >= analysis['threshold'] and not row['alerted'] and row['detection_status'] == 'evaluated' and reviewed is None
        row['reviewed'] = reviewed is not None
    analysis['rows'].sort(key=lambda r: (not r['reviewed'], r['priority_score'] or 0), reverse=True)
    hosts = {}
    for row in analysis['rows']:
        host = hosts.setdefault(row['src_ip'] or 'unknown', dict(ip=row['src_ip'], packets=0, candidates=0, alerts=0, max_score=0))
        host['packets'] += 1
        host['alerts'] += int(row['alerted'])
        host['candidates'] += int(row['candidate'] and not row['reviewed'])
        host['max_score'] = max(host['max_score'], row['priority_score'] or 0)
    analysis.update(candidates=sum(r['candidate'] and not r['reviewed'] for r in analysis['rows']),
                    generated_at=utc_now(), hosts=sorted(hosts.values(), key=lambda h: h['max_score'], reverse=True)[:10])
    analysis['learning'] = dict(model=f'byte-mlp-8x{len(model["w1"])}x1-v1', revision=state.get('revision', 0),
                               ready=ready, status='experimental' if ready else 'warming_up', counts=dict(counts),
                               total=len(examples), capacity=MAX_EXAMPLES, updated_at=state.get('updated_at'),
                               parameters=model, feature_names=FEATURES, history=state.get('history', []),
                               audit=state.get('audit', [])[-10:], threshold=analysis['threshold'] / 100,
                               effectiveness=model_effectiveness(state),
                               training=state.get('training', {
                                   'mode': 'online_mini_batch', 'updates': 0, 'batch_size': 0,
                                   'batch_limit': ONLINE_BATCH_SIZE, 'epochs_per_update': ONLINE_EPOCHS,
                                   'samples_seen': 0, 'weights_persisted': True,
                               }))
    return analysis
