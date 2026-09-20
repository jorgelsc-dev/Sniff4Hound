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
import threading
from collections import Counter, defaultdict

from .packet_ai import packet_bytes
from .utils import utc_now

FEATURES = ['Intensidad media', 'Desviación', 'Entropía', 'Bytes cero',
            'Texto imprimible', 'Contraste horizontal', 'Contraste vertical', 'Ocupación']
# Capped per label, not as one shared pool: auto-labelled training feedback
# (sniffer._store_packet, when training_enabled is on) produces benign
# examples far more often than malicious ones - real high/critical alerts
# are rare - so a single shared FIFO cap would let a burst of benign
# examples evict every retained malicious one long before real attack
# traffic ever shows up again. See _trim_examples_per_class().
MAX_EXAMPLES_PER_CLASS = 500
ONLINE_BATCH_SIZE = 8
ONLINE_EPOCHS = 8
ONLINE_LEARNING_RATE = 0.04
DEFAULT_HIDDEN_NEURONS = 6
# Depth and width are the operator's own call - the only floor is what keeps
# a layer mathematically meaningful (at least 1 neuron, at least 1 hidden
# layer so this never degrades into a linear model - see
# normalize_hidden_sizes). There is deliberately no ceiling: pick an
# extreme shape and you pay for it in training time (this trainer is plain
# Python, O(total weights * examples * epochs) per retrain), not in a
# rejected request.
MIN_HIDDEN_NEURONS = 1
MIN_HIDDEN_LAYERS = 1
DEFAULT_HIDDEN_SIZES = [DEFAULT_HIDDEN_NEURONS]
MAX_IMPORTED_WEIGHT_ABS = 1_000_000.0
# How often (in newly retained examples) a feedback event re-runs the
# architecture search, and how much accuracy a candidate shape has to beat
# the current one by before it's worth surfacing as a suggestion - small
# enough to catch a real improvement, large enough that noise from one extra
# example doesn't flip the recommendation every review.
SUGGESTION_CHECK_INTERVAL = 5
SUGGESTION_MIN_IMPROVEMENT = 0.03
# Candidates scoring within this margin of the best one are considered a
# wash, and the smallest of them wins instead - otherwise, with hidden_sizes
# now unbounded, a negligible accuracy blip would always push the
# recommendation toward the biggest shape tried.
SUGGESTION_TIE_MARGIN = 0.015
# Below this many examples of EACH class, a train/validation split would
# leave too few held-out examples per class to score reliably, so the search
# falls back to measuring every candidate on the same examples it trained on.
VALIDATION_MIN_PER_CLASS = 6
VALIDATION_FRACTION = 0.3
# Tournament: TOURNAMENT_CANDIDATES_PER_ROUND shapes train side by side each
# round (see run_tournament_round()); the winner carries into the next round
# alongside fresh random challengers filling the remaining slots. This never
# stops on its own - it keeps running, round after round, for as long as
# training_enabled stays on (see store.py's _run_ai_tournament()), so a flat
# stretch of rounds isn't a reason to give up, just bad luck on that round's
# random challengers.
TOURNAMENT_CANDIDATES_PER_ROUND = 3


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
    """Coerce to a valid list of layer widths - never empty (an all-linear
    network with no hidden layer isn't what "capar neuronas" was asking
    for) and never non-positive, but otherwise uncapped - see the module
    constants above."""
    sizes = list(hidden_sizes) if hidden_sizes else list(DEFAULT_HIDDEN_SIZES)
    sizes = [max(MIN_HIDDEN_NEURONS, int(size)) for size in sizes]
    return sizes or list(DEFAULT_HIDDEN_SIZES)


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


def train(examples, hidden_sizes=None, on_epoch=None):
    """``on_epoch(epoch, total_epochs, loss)``, if given, is called after
    every epoch (1-indexed) - used by run_tournament_round() to report live
    per-candidate progress while a full 80-epoch retrain is still running,
    without changing anything about the training itself."""
    model = initial_model(hidden_sizes)
    history = []
    total_epochs = 80 if examples else 0
    for epoch in range(total_epochs):
        loss = 0.0
        for example in examples:
            x, y = example['features'], int(example['label'] == 'malicious')
            output = _backprop_step(model, x, y, example['confidence'], 0.08)
            loss -= y * math.log(max(output, 1e-12)) + (1 - y) * math.log(max(1 - output, 1e-12))
        epoch_loss = round(loss / len(examples), 6)
        if epoch % 10 == 0 or epoch == 79:
            history.append({'epoch': epoch + 1, 'loss': epoch_loss})
        if on_epoch is not None:
            on_epoch(epoch + 1, total_epochs, epoch_loss)
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
    set the model never trained on. `evaluation_mode` is always
    'resubstitution' here (never a held-out split, unlike
    run_tournament_round() below) - callers must not label this "accuracy"
    without qualifying it (FAQA finding 1.25: a model that always predicts
    "benign" over a mostly-benign dataset scores high here despite zero
    real detection ability)."""
    examples = state.get('examples', [])
    counts = Counter(e['label'] for e in examples)
    ready = counts['benign'] >= 3 and counts['malicious'] >= 3
    if not ready or not examples:
        return {
            'ready': False, 'accuracy': None, 'correct': 0, 'total': len(examples),
            'evaluation_mode': 'resubstitution',
        }
    model = state.get('model')
    if not is_current_model_shape(model):
        model = initial_model()
    correct = sum(
        1 for example in examples
        if ('malicious' if forward(model, example['features'])[1] >= 0.5 else 'benign') == example['label']
    )
    return {
        'ready': True, 'accuracy': round(correct / len(examples), 4), 'correct': correct, 'total': len(examples),
        'evaluation_mode': 'resubstitution',
    }


def _accuracy_for(model, examples):
    if not examples:
        return None
    correct = sum(
        1 for example in examples
        if ('malicious' if forward(model, example['features'])[1] >= 0.5 else 'benign') == example['label']
    )
    return round(correct / len(examples), 4)


def _hidden_size_candidates(hidden_sizes):
    """A handful of neighbouring shapes - a layer widened/narrowed by a step
    proportional to its own size, the network made one layer deeper/
    shallower - rather than an exhaustive search: every candidate here means
    a full retrain, so this stays a bounded coordinate-descent step instead
    of a combinatorial sweep over every possible width/depth. Proportional
    steps (instead of a flat +/-3) keep the search meaningful whether the
    current shape is a 6-neuron layer or a 200-neuron one."""
    seen = {tuple(hidden_sizes)}
    candidates = []

    def add(sizes):
        sizes = [max(MIN_HIDDEN_NEURONS, int(s)) for s in sizes]
        key = tuple(sizes)
        if not sizes or key in seen:
            return
        seen.add(key)
        candidates.append(sizes)

    for i in range(len(hidden_sizes)):
        step = max(3, round(hidden_sizes[i] * 0.5))
        wider, narrower = list(hidden_sizes), list(hidden_sizes)
        wider[i] += step
        narrower[i] -= step
        add(wider)
        add(narrower)
    add(hidden_sizes + [round(sum(hidden_sizes) / len(hidden_sizes))])
    if len(hidden_sizes) > MIN_HIDDEN_LAYERS:
        add(hidden_sizes[:-1])
    return candidates


def _split_train_validation(examples):
    """Stratified holdout split (by label): a deterministic (seeded)
    shuffle so repeated calls over the same examples agree, then the same
    proportion held out from each class so the split doesn't skew the
    benign/malicious balance the classifier is scored on.

    Used by suggest_architecture so a bigger/deeper candidate is scored on
    examples it never trained on, rather than on resubstitution accuracy
    alone - which would just reward whichever candidate memorized the
    training set best, an increasingly real risk now that hidden layer
    count/width has no upper bound.
    """
    by_label = defaultdict(list)
    for example in examples:
        by_label[example['label']].append(example)
    rng = random.Random(0)
    train_examples, validation_examples = [], []
    for label_examples in by_label.values():
        shuffled = list(label_examples)
        rng.shuffle(shuffled)
        cut = max(1, round(len(shuffled) * (1 - VALIDATION_FRACTION)))
        cut = min(cut, len(shuffled) - 1) if len(shuffled) > 1 else len(shuffled)
        train_examples.extend(shuffled[:cut])
        validation_examples.extend(shuffled[cut:])
    return train_examples, validation_examples


def suggest_architecture(state, hidden_sizes, dismissed=(), report=None):
    """Try a bounded set of neighbouring hidden-layer shapes against the
    operator's own retained labels and report the best one, if any, that
    beats the current shape by a real margin.

    Once each class has enough retained examples (VALIDATION_MIN_PER_CLASS),
    the current shape and every candidate are trained on the same held-out
    split (_split_train_validation) and scored on the portion they didn't
    train on, so the comparison reflects generalization rather than just
    fit-to-training-data - with hidden_sizes now unbounded, resubstitution
    accuracy alone would systematically favor the biggest candidate tried.
    Below that threshold there isn't enough data to hold any out reliably,
    so it falls back to scoring every shape on the same examples it trained
    on, same as before. A candidate has to beat the current shape by
    SUGGESTION_MIN_IMPROVEMENT to be worth surfacing at all, and among
    candidates within SUGGESTION_TIE_MARGIN of the best score, the smallest
    one wins (Occam's razor) rather than always the top-scoring one, so the
    recommendation doesn't drift toward ever-larger networks for noise-level
    gains. Never applied automatically - see NeuralNetworkConfigPanel.vue's
    suggestion banner - only surfaced for an operator to accept or dismiss.
    """
    examples = state.get('examples', [])
    counts = Counter(e['label'] for e in examples)
    if report is not None:
        report.update(status='waiting_labels', candidates=[], checked_at=utc_now(), revision=state.get('revision', 0))
    if counts['benign'] < 3 or counts['malicious'] < 3:
        return None
    current_shape = normalize_hidden_sizes(hidden_sizes)
    use_holdout = counts['benign'] >= VALIDATION_MIN_PER_CLASS and counts['malicious'] >= VALIDATION_MIN_PER_CLASS
    train_examples, eval_examples = _split_train_validation(examples) if use_holdout else (examples, examples)
    current_model, _ = train(train_examples, hidden_sizes=current_shape)
    current_accuracy = _accuracy_for(current_model, eval_examples)
    if current_accuracy is None:
        return None
    if report is not None:
        report.update(status='complete', current_hidden_sizes=current_shape, current_accuracy=current_accuracy)
    dismissed_keys = {tuple(normalize_hidden_sizes(d)) for d in dismissed}
    scored = []
    for candidate in _hidden_size_candidates(current_shape):
        if tuple(candidate) in dismissed_keys:
            continue
        model, _ = train(train_examples, hidden_sizes=candidate)
        accuracy = _accuracy_for(model, eval_examples)
        if accuracy is None:
            continue
        if report is not None:
            report['candidates'].append({'hidden_sizes': candidate, 'accuracy': accuracy})
        scored.append({'hidden_sizes': candidate, 'accuracy': accuracy})
    if not scored:
        return None
    best_accuracy = max(c['accuracy'] for c in scored)
    if best_accuracy < current_accuracy + SUGGESTION_MIN_IMPROVEMENT:
        return None
    contenders = [c for c in scored if c['accuracy'] >= best_accuracy - SUGGESTION_TIE_MARGIN]
    best = min(contenders, key=lambda c: (sum(c['hidden_sizes']), len(c['hidden_sizes'])))
    return {
        'hidden_sizes': best['hidden_sizes'],
        'current_hidden_sizes': current_shape,
        'current_accuracy': current_accuracy,
        'suggested_accuracy': best['accuracy'],
    }


TOURNAMENT_STRUCTURE_DELTA_RANGE = (-2, -1, 1, 2)


def _random_hidden_sizes(rng, seed_shape):
    """A random neighbour of seed_shape for a tournament challenger - a
    small, local mutation each round rather than a big structural jump:
    both the layer count and each individual layer's neuron count move by
    at most +/-2 from seed_shape (TOURNAMENT_STRUCTURE_DELTA_RANGE), never a
    proportional/unbounded step. A layer beyond seed_shape's own depth (the
    challenger grew deeper) is seeded from seed_shape's last layer width
    before its own +/-2 mutation is applied."""
    seed_shape = normalize_hidden_sizes(seed_shape)
    new_layer_count = max(MIN_HIDDEN_LAYERS, len(seed_shape) + rng.choice(TOURNAMENT_STRUCTURE_DELTA_RANGE))
    sizes = []
    for i in range(new_layer_count):
        base = seed_shape[i] if i < len(seed_shape) else seed_shape[-1]
        sizes.append(max(MIN_HIDDEN_NEURONS, base + rng.choice(TOURNAMENT_STRUCTURE_DELTA_RANGE)))
    return normalize_hidden_sizes(sizes)


def tournament_round_shapes(champion_shape, rng, *, count=TOURNAMENT_CANDIDATES_PER_ROUND, include_champion=True):
    """`count` shapes for one tournament round: the reigning champion (if
    `include_champion`) plus fresh random neighbours filling the rest.
    Round 1 has no reigning champion yet - pass include_champion=False (still
    seeded from champion_shape, e.g. the production model's current shape,
    as a neutral starting point) to draw every slot fresh."""
    champion_shape = normalize_hidden_sizes(champion_shape)
    shapes = [list(champion_shape)] if include_champion else []
    seen = {tuple(champion_shape)}
    attempts = 0
    while len(shapes) < count and attempts < count * 20:
        attempts += 1
        candidate = _random_hidden_sizes(rng, champion_shape)
        key = tuple(candidate)
        if key in seen:
            continue
        seen.add(key)
        shapes.append(candidate)
    return shapes


def run_tournament_round(examples, shapes, progress=None, progress_lock=None):
    """Train every shape in `shapes` side by side and return one
    ``{hidden_sizes, accuracy, parameters}`` entry per shape, same order as
    `shapes` - unlike suggest_architecture() above, the trained weights
    (`parameters`) are kept so the caller can render each candidate live,
    not just compare a final accuracy number.

    Each candidate trains on its own `threading.Thread`. This trainer is
    plain Python with no numpy, so under the GIL threads buy interleaved
    progress rather than real CPU parallelism - that's fine here, nothing
    depends on the candidates finishing at the same wall-clock time, only on
    each reporting its own progress independently.

    `progress`, if given, is a dict this function writes into - one entry per
    candidate, keyed by its index in `shapes` - so a caller on another thread
    can read live epoch/loss updates while training is still running.
    `progress_lock` must be given whenever `progress` is, and guards every
    read/write of it.
    """
    counts = Counter(e['label'] for e in examples)
    use_holdout = counts['benign'] >= VALIDATION_MIN_PER_CLASS and counts['malicious'] >= VALIDATION_MIN_PER_CLASS
    train_examples, eval_examples = _split_train_validation(examples) if use_holdout else (examples, examples)
    # Uniform across the whole round (same use_holdout for every candidate),
    # carried on each result rather than as a separate return value so a
    # caller indexing into the list (existing contract) sees it for free.
    # Below VALIDATION_MIN_PER_CLASS this falls back to resubstitution - the
    # same "trained on what it's scored on" weakness model_effectiveness()
    # has, and the UI must say so rather than implying every tournament
    # round validates on unseen data (finding 1.25).
    evaluation_mode = 'holdout' if use_holdout else 'resubstitution'

    results = [None] * len(shapes)

    def _run_one(index, shape):
        state = {'hidden_sizes': shape, 'epoch': 0, 'total_epochs': 80, 'loss': None, 'status': 'training'}
        if progress is not None:
            with progress_lock:
                progress[index] = dict(state)

        def _on_epoch(epoch, total_epochs, loss):
            state.update(epoch=epoch, total_epochs=total_epochs, loss=loss)
            if progress is not None:
                with progress_lock:
                    progress[index] = dict(state)

        model, _ = train(train_examples, hidden_sizes=shape, on_epoch=_on_epoch)
        accuracy = _accuracy_for(model, eval_examples)
        results[index] = {
            'hidden_sizes': shape, 'accuracy': accuracy, 'parameters': model,
            'evaluation_mode': evaluation_mode,
        }
        state.update(status='done', accuracy=accuracy)
        if progress is not None:
            with progress_lock:
                progress[index] = dict(state)

    threads = [threading.Thread(target=_run_one, args=(index, shape), daemon=True) for index, shape in enumerate(shapes)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


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
    for size in hidden_sizes:
        if size < MIN_HIDDEN_NEURONS:
            raise ValueError(f'Cada capa oculta debe tener al menos {MIN_HIDDEN_NEURONS} neurona(s).')
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


def _trim_examples_per_class(examples, limit):
    """Evict down to `limit` examples of EACH label independently, oldest
    first within a label, instead of one shared FIFO over the whole list -
    see MAX_EXAMPLES_PER_CLASS. The overall chronological order is
    preserved (only the excess oldest rows of an over-limit label are
    dropped) since update_feedback's online mini-batch takes "the most
    recent N examples" off the end of this same list and needs that
    ordering to actually mean recency."""
    counts = Counter(e['label'] for e in examples)
    overflow = {label: max(0, count - limit) for label, count in counts.items()}
    if not any(overflow.values()):
        return examples
    dropped = defaultdict(int)
    trimmed = []
    for example in examples:
        label = example['label']
        if dropped[label] < overflow.get(label, 0):
            dropped[label] += 1
            continue
        trimmed.append(example)
    return trimmed


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
    examples = _trim_examples_per_class(examples, MAX_EXAMPLES_PER_CLASS)
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
        # bounded even when the retained audit set reaches MAX_EXAMPLES_PER_CLASS.
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
                               total=len(examples), capacity=MAX_EXAMPLES_PER_CLASS * 2, updated_at=state.get('updated_at'),
                               parameters=model, hidden_sizes=hidden_sizes_of(model), feature_names=FEATURES,
                               history=state.get('history', []), audit=state.get('audit', [])[-10:],
                               threshold=analysis['threshold'] / 100, effectiveness=model_effectiveness(state),
                               training=state.get('training', {
                                   'mode': 'online_mini_batch', 'updates': 0, 'batch_size': 0,
                                   'batch_limit': ONLINE_BATCH_SIZE, 'epochs_per_update': ONLINE_EPOCHS,
                                   'samples_seen': 0, 'weights_persisted': True,
                               }))
    return analysis
