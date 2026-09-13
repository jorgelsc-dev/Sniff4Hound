"""Small inspectable supervised network trained only from operator labels.

Normal feedback uses a tiny online mini-batch and starts from the weights saved
by the previous update.  The full labelled set is never replayed for each click.
Training loss is not an estimate of production detection accuracy.

Architecture: FEATURES inputs -> zero or more tanh hidden layers (each an
operator-configured width) -> one sigmoid output neuron. A model is
``{"layers": [{"w": [[...]], "b": [...]}, ...]}`` - one entry per weight
matrix, the last one always being the 1-neuron output layer. Persisted
weights are shape-bound to whatever hidden_sizes they were last (re)trained
with; forward() infers shape from the model itself so it never errors on a
mismatch, but callers that change hidden_sizes (update_feedback,
rebuild_for_hidden_sizes) have to retrain from scratch rather than pretend
mismatched weights are still meaningful.
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
MIN_HIDDEN_LAYERS = 1
MAX_HIDDEN_LAYERS = 4
DEFAULT_HIDDEN_SIZES = [DEFAULT_HIDDEN_NEURONS]
MAX_IMPORTED_WEIGHT_ABS = 1_000_000.0


def features(data):
    if not data:
        raise ValueError('No hay bytes suficientes para extraer características.')
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


def normalize_hidden_sizes(hidden_sizes):
    """Coerce to a valid, bounded list of layer widths - never empty (an
    all-linear network with no hidden layer isn't what "capar neuronas" was
    asking for), never absurdly deep or wide."""
    sizes = list(hidden_sizes) if hidden_sizes else list(DEFAULT_HIDDEN_SIZES)
    sizes = [max(MIN_HIDDEN_NEURONS, min(MAX_HIDDEN_NEURONS, int(size))) for size in sizes]
    sizes = sizes[:MAX_HIDDEN_LAYERS] or list(DEFAULT_HIDDEN_SIZES)
    return sizes


def initial_model(hidden_sizes=None):
    hidden_sizes = normalize_hidden_sizes(hidden_sizes)
    rng = random.Random(41)
    sizes = [len(FEATURES)] + hidden_sizes + [1]
    layers = []
    for n_in, n_out in zip(sizes, sizes[1:]):
        layers.append({
            'w': [[rng.uniform(-0.6, 0.6) for _ in range(n_in)] for _ in range(n_out)],
            'b': [0.0] * n_out,
        })
    return {'layers': layers}


def hidden_sizes_of(model):
    """The configured widths a persisted model was actually built with -
    read from the model itself (every layer but the last, which is always
    the 1-neuron output), not from whatever is currently configured."""
    return [len(layer['b']) for layer in model['layers'][:-1]]


def is_current_model_shape(model):
    """False for a model saved before the multi-layer rewrite - the old
    shape was a hardcoded two-layer {"w1","b1","w2","b2"} dict, with no
    "layers" key at all. A store predating this change can have exactly
    that sitting in its persisted ai_learning_state; treating it as "no
    model" (rather than crashing on model['layers']) is what lets an
    existing install self-heal on its next feedback event or read instead
    of leaving the AI view permanently broken."""
    return isinstance(model, dict) and isinstance(model.get('layers'), list) and bool(model['layers'])


def _forward_full(model, x):
    """forward() plus the intermediate activations backprop needs. Returns
    ``activations`` (input, then one entry per layer's output, tanh for
    every hidden layer and sigmoid for the last) - never empty since a model
    always has at least the output layer."""
    activations = [x]
    layers = model['layers']
    for idx, layer in enumerate(layers):
        current = activations[-1]
        if len(layer.get('w', [])) != len(layer.get('b', [])):
            raise ValueError('Las dimensiones internas del modelo no coinciden.')
        for row in layer.get('w', []):
            if len(row) != len(current):
                raise ValueError('Las dimensiones internas del modelo no coinciden.')
        z = [sum(w * v for w, v in zip(row, current)) + b for row, b in zip(layer['w'], layer['b'])]
        if idx == len(layers) - 1:
            activations.append([1 / (1 + math.exp(-max(-30, min(30, z[0]))))])
        else:
            activations.append([math.tanh(v) for v in z])
    return activations


def forward(model, x):
    activations = _forward_full(model, x)
    hidden_layers = activations[1:-1]
    output = activations[-1][0]
    return hidden_layers, output


def _backprop_step(model, x, y, confidence, learning_rate):
    """One gradient-descent step for one labelled example, arbitrary depth.

    Standard backprop: sigmoid output + cross-entropy loss gives a delta of
    (output - y) at the output layer; each hidden layer's delta is the next
    layer's delta projected back through its weights and scaled by the tanh
    derivative (1 - a^2). Returns the output activation from *before* this
    step's update, for loss reporting."""
    activations = _forward_full(model, x)
    layers = model['layers']
    output = activations[-1][0]
    deltas = [None] * len(layers)
    deltas[-1] = [(output - y) * confidence / 3]
    for idx in range(len(layers) - 2, -1, -1):
        next_layer = layers[idx + 1]
        next_delta = deltas[idx + 1]
        a = activations[idx + 1]
        deltas[idx] = [
            sum(next_delta[k] * next_layer['w'][k][j] for k in range(len(next_delta))) * (1 - a[j] * a[j])
            for j in range(len(a))
        ]
    for idx, layer in enumerate(layers):
        a_in = activations[idx]
        delta = deltas[idx]
        if len(layer['w']) != len(layer['b']) or len(delta) != len(layer['b']):
            raise ValueError('Las dimensiones internas del modelo no coinciden.')
        for j in range(len(layer['b'])):
            if len(layer['w'][j]) != len(a_in):
                raise ValueError('Las dimensiones internas del modelo no coinciden.')
            layer['b'][j] -= learning_rate * delta[j]
            row = layer['w'][j]
            dj = delta[j]
            for i in range(len(a_in)):
                row[i] -= learning_rate * dj * a_in[i]
    return output


def train(examples, hidden_sizes=None):
    model = initial_model(hidden_sizes)
    history = []
    for epoch in range(80 if examples else 0):
        loss = 0.0
        for example in examples:
            x, y = example['features'], int(example['label'] == 'malicious')
            output = _backprop_step(model, x, y, example['confidence'], 0.08)
            loss -= y * math.log(max(output, 1e-12)) + (1 - y) * math.log(max(1 - output, 1e-12))
        if epoch % 10 == 0 or epoch == 79:
            history.append({'epoch': epoch + 1, 'loss': round(loss / len(examples), 6)})
    return model, history


def train_incremental(model, examples, *, epochs=ONLINE_EPOCHS, learning_rate=ONLINE_LEARNING_RATE, step=0,
                       hidden_sizes=None):
    """Update persisted weights with one small, bounded mini-batch.

    Keeping this separate from ``train`` preserves the deterministic full
    trainer for tests/diagnostics while production feedback stays O(1) as the
    saved example collection grows.
    """
    updated = copy.deepcopy(model) if model else initial_model(hidden_sizes)
    if not examples:
        return updated, []
    loss = 0.0
    for _epoch in range(max(1, int(epochs))):
        loss = 0.0
        for example in examples:
            x, y = example['features'], int(example['label'] == 'malicious')
            output = _backprop_step(updated, x, y, example['confidence'], learning_rate)
            loss -= y * math.log(max(output, 1e-12)) + (1 - y) * math.log(max(1 - output, 1e-12))
    return updated, [{
        'epoch': int(step) + 1,
        'loss': round(loss / len(examples), 6),
        'batch_size': len(examples),
        'epochs': max(1, int(epochs)),
    }]


def rebuild_for_hidden_sizes(state, hidden_sizes=None):
    """Retrain from the retained examples under a new hidden-layer shape.

    Persisted weights are shape-bound to whatever hidden_sizes they were
    last trained with - forward() would still run against a mismatched
    shape without erroring (it infers shape from the model itself), but the
    resulting predictions would be meaningless carry-over from the old
    architecture. Called right when an operator changes the layer/neuron
    layout in Settings, rather than waiting for the next feedback event to
    notice."""
    examples = list(state.get('examples', []))
    revision = int(state.get('revision', 0)) + 1
    now = utc_now()
    if not examples:
        model = initial_model(hidden_sizes)
        entry = {'epoch': revision, 'loss': None, 'batch_size': 0, 'epochs': 0}
    else:
        model, full_history = train(examples, hidden_sizes=hidden_sizes)
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
    model = state.get('model')
    if not is_current_model_shape(model):
        model = initial_model()
    correct = sum(
        1 for example in examples
        if ('malicious' if forward(model, example['features'])[1] >= 0.5 else 'benign') == example['label']
    )
    return {'ready': True, 'accuracy': round(correct / len(examples), 4), 'correct': correct, 'total': len(examples)}


def export_model(state):
    """Structure + weights only (Settings > IA > Exportar) - not the
    labelled examples, which are the operator's own review history rather
    than part of "the model"."""
    model = state.get('model')
    if not is_current_model_shape(model):
        model = initial_model()
    return {
        'format': 'sniff4hound-ai-model-v1',
        'hidden_sizes': hidden_sizes_of(model),
        'model': model,
        'revision': state.get('revision', 0),
        'exported_at': utc_now(),
    }


def _validate_imported_model(payload):
    if not isinstance(payload, dict):
        raise ValueError('El archivo no contiene un modelo válido.')
    model = payload.get('model')
    if not isinstance(model, dict) or not isinstance(model.get('layers'), list) or not model['layers']:
        raise ValueError('El modelo importado no tiene capas.')
    sizes = [len(FEATURES)]
    normalized_layers = []

    def _number(value, where: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            raise ValueError(f'El valor {where} debe ser numérico y finito.')
        parsed = float(value)
        if abs(parsed) > MAX_IMPORTED_WEIGHT_ABS:
            raise ValueError(f'El valor {where} excede el máximo permitido ({MAX_IMPORTED_WEIGHT_ABS:g}).')
        return parsed

    for layer_index, layer in enumerate(model['layers']):
        if not isinstance(layer, dict) or 'w' not in layer or 'b' not in layer:
            raise ValueError('Cada capa debe tener pesos (w) y sesgos (b).')
        w, b = layer['w'], layer['b']
        if not isinstance(w, list) or not isinstance(b, list) or len(w) != len(b):
            raise ValueError('Las dimensiones de w y b no coinciden en una capa.')
        normalized_w = []
        for row_index, row in enumerate(w):
            if not isinstance(row, list) or len(row) != sizes[-1]:
                raise ValueError(
                    f'Una capa espera {sizes[-1]} entradas pero encontró {len(row) if isinstance(row, list) else "?"}.'
                )
            normalized_w.append([
                _number(value, f'w[{layer_index}][{row_index}][{value_index}]')
                for value_index, value in enumerate(row)
            ])
        normalized_b = [
            _number(value, f'b[{layer_index}][{value_index}]')
            for value_index, value in enumerate(b)
        ]
        normalized_layers.append({'w': normalized_w, 'b': normalized_b})
        sizes.append(len(b))
    if sizes[-1] != 1:
        raise ValueError('La última capa debe tener exactamente 1 neurona de salida.')
    hidden_sizes = sizes[1:-1]
    if not hidden_sizes:
        raise ValueError('El modelo debe tener al menos una capa oculta.')
    if len(hidden_sizes) > MAX_HIDDEN_LAYERS:
        raise ValueError(f'Máximo {MAX_HIDDEN_LAYERS} capas ocultas.')
    for size in hidden_sizes:
        if not (MIN_HIDDEN_NEURONS <= size <= MAX_HIDDEN_NEURONS):
            raise ValueError(f'Cada capa oculta debe tener entre {MIN_HIDDEN_NEURONS} y {MAX_HIDDEN_NEURONS} neuronas.')
    return {'layers': normalized_layers}, hidden_sizes


def import_model(state, payload):
    """Adopt an imported model's weights and architecture wholesale. The
    retained examples (review history) are kept as-is - only the weights
    (and the hidden_sizes they imply) change; a future feedback event will
    fine-tune from here rather than the imported weights being immediately
    overwritten by a stale-architecture retrain, since hidden_sizes_of() on
    the imported model already matches what gets adopted."""
    model, hidden_sizes = _validate_imported_model(payload)
    revision = int(state.get('revision', 0)) + 1
    now = utc_now()
    history = (list(state.get('history', [])) + [
        {'epoch': revision, 'loss': None, 'batch_size': 0, 'epochs': 0}
    ])[-30:]
    previous_training = state.get('training', {}) if isinstance(state.get('training'), dict) else {}
    training = {
        'mode': 'imported',
        'updates': int(previous_training.get('updates', state.get('revision', 0))) + 1,
        'batch_size': 0,
        'batch_limit': ONLINE_BATCH_SIZE,
        'epochs_per_update': ONLINE_EPOCHS,
        'samples_seen': int(previous_training.get('samples_seen', 0)),
        'weights_persisted': True,
    }
    return dict(revision=revision, examples=state.get('examples', []), model=model, history=history,
                audit=state.get('audit', []), training=training, updated_at=now), hidden_sizes


def update_feedback(state, packet, label, confidence, note, *, hidden_sizes=None):
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
    normalized_sizes = normalize_hidden_sizes(hidden_sizes)
    # A hidden_sizes configured after this state's model was last (re)trained
    # leaves persisted weights shape-bound to the old shape - forward() would
    # still run without erroring (it infers shape from the model itself) but
    # the predictions would be meaningless carry-over. Force a full retrain
    # here too, not just from rebuild_for_hidden_sizes(), in case a feedback
    # event races a config change. A model saved before the multi-layer
    # rewrite (no "layers" key at all - see is_current_model_shape) gets the
    # same treatment: hidden_sizes_of() cannot even be computed for it, so
    # treat "existing but incompatible shape" as equivalent to "stale size" -
    # both need the same full retrain from the retained examples. A model
    # that simply doesn't exist yet (fresh state) is not stale, just new.
    existing_model_current = bool(existing_model) and is_current_model_shape(existing_model)
    stale_architecture = bool(existing_model) and (
        not existing_model_current or hidden_sizes_of(existing_model) != normalized_sizes
    )
    if not examples:
        # With no remaining evidence there is nothing legitimate to retain.
        model = initial_model(normalized_sizes)
        new_history = [{'epoch': revision, 'loss': None, 'batch_size': 0, 'epochs': 0}]
        batch_size = 0
    elif stale_architecture:
        model, full_history = train(examples, hidden_sizes=normalized_sizes)
        entry = dict(full_history[-1]) if full_history else {'loss': None}
        entry.update(epoch=revision, batch_size=len(examples))
        new_history = [entry]
        batch_size = len(examples)
    elif changed_example is None:
        # Retraction removes the example from the replay buffer immediately.
        # Existing weights remain the accumulated online knowledge; future
        # small updates will move them without an expensive full rebuild.
        model = copy.deepcopy(existing_model or initial_model(normalized_sizes))
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
            existing_model or initial_model(normalized_sizes), batch, step=revision - 1, hidden_sizes=normalized_sizes
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


def learning_snapshot(state, packets, analysis, hidden_sizes=None):
    model = state.get('model')
    if not is_current_model_shape(model):
        model = initial_model(hidden_sizes)
    examples = state.get('examples', [])
    counts = Counter(e['label'] for e in examples)
    ready = counts['benign'] >= 3 and counts['malicious'] >= 3
    by_key = {e['key']: e for e in examples}
    by_id = {p['id']: p for p in packets}
    for row in analysis['rows']:
        packet = by_id[row['id']]
        data, _, _ = packet_bytes(packet)
        x = features(data) if data else None
        hidden_layers, output = forward(model, x) if x else ([], None)
        reviewed = by_key.get(fingerprint(packet)) if data else None
        row.update(neural_score=round(output * 100, 1) if ready and output is not None else None,
                   activations={'input': x, 'hidden_layers': hidden_layers, 'output': output},
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
    model_id = 'x'.join(str(n) for n in ([len(FEATURES)] + hidden_sizes_of(model) + [1]))
    analysis['learning'] = dict(model=f'byte-mlp-{model_id}-v1', revision=state.get('revision', 0),
                               ready=ready, status='experimental' if ready else 'warming_up', counts=dict(counts),
                               total=len(examples), capacity=MAX_EXAMPLES, updated_at=state.get('updated_at'),
                               parameters=model, hidden_sizes=hidden_sizes_of(model), feature_names=FEATURES,
                               history=state.get('history', []), audit=state.get('audit', [])[-10:],
                               threshold=analysis['threshold'] / 100, effectiveness=model_effectiveness(state),
                               training=state.get('training', {
                                   'mode': 'online_mini_batch', 'updates': 0, 'batch_size': 0,
                                   'batch_limit': ONLINE_BATCH_SIZE, 'epochs_per_update': ONLINE_EPOCHS,
                                   'samples_seen': 0, 'weights_persisted': True,
                               }))
    return analysis
