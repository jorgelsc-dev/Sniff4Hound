"""Small inspectable supervised network trained only from operator labels.

Bounded deterministic replay makes corrections reversible and repeated clicks
idempotent. Training loss is not an estimate of production detection accuracy.
"""
import hashlib
import math
import random
from collections import Counter

from .packet_ai import packet_bytes
from .utils import utc_now

FEATURES = ['Intensidad media', 'Desviación', 'Entropía', 'Bytes cero',
            'Texto imprimible', 'Contraste horizontal', 'Contraste vertical', 'Ocupación']
MAX_EXAMPLES = 200


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


def initial_model():
    rng = random.Random(41)
    return dict(w1=[[rng.uniform(-0.6, 0.6) for _ in FEATURES] for _ in range(6)],
                b1=[0.0] * 6, w2=[rng.uniform(-0.6, 0.6) for _ in range(6)], b2=0.0)


def forward(model, x):
    hidden = [math.tanh(sum(w * v for w, v in zip(weights, x)) + bias)
              for weights, bias in zip(model['w1'], model['b1'])]
    logit = sum(w * h for w, h in zip(model['w2'], hidden)) + model['b2']
    output = 1 / (1 + math.exp(-max(-30, min(30, logit))))
    return hidden, output


def train(examples):
    model = initial_model()
    history = []
    for epoch in range(80 if examples else 0):
        loss = 0.0
        for example in examples:
            x, y = example['features'], int(example['label'] == 'malicious')
            hidden, output = forward(model, x)
            loss -= y * math.log(max(output, 1e-12)) + (1 - y) * math.log(max(1 - output, 1e-12))
            delta = (output - y) * example['confidence'] / 3
            hidden_delta = [delta * w * (1 - h * h) for w, h in zip(model['w2'], hidden)]
            for j in range(6):
                model['w2'][j] -= 0.08 * delta * hidden[j]
                model['b1'][j] -= 0.08 * hidden_delta[j]
                for i in range(8):
                    model['w1'][j][i] -= 0.08 * hidden_delta[j] * x[i]
            model['b2'] -= 0.08 * delta
        if epoch % 10 == 0 or epoch == 79:
            history.append({'epoch': epoch + 1, 'loss': round(loss / len(examples), 6)})
    return model, history


def update_feedback(state, packet, label, confidence, note):
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
    if label != 'unreviewed':
        examples.append(dict(key=key, packet_id=packet['id'], proto=packet.get('proto'), features=features(data),
                             label=label, confidence=confidence, note=note, updated_at=now))
    examples = examples[-MAX_EXAMPLES:]
    model, history = train(examples)
    revision = state.get('revision', 0) + 1
    audit = (state.get('audit', []) + [dict(packet_id=packet['id'], label=label, confidence=confidence,
             note=note, previous=previous['label'] if previous else None, revision=revision, at=now)])[-100:]
    return dict(revision=revision, examples=examples, model=model, history=history, audit=audit, updated_at=now)


def learning_snapshot(state, packets, analysis):
    model = state.get('model') or initial_model()
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
    analysis['learning'] = dict(model='byte-mlp-8x6x1-v1', revision=state.get('revision', 0), ready=ready,
                               status='experimental' if ready else 'warming_up', counts=dict(counts),
                               total=len(examples), capacity=MAX_EXAMPLES, updated_at=state.get('updated_at'),
                               parameters=model, feature_names=FEATURES, history=state.get('history', []),
                               audit=state.get('audit', [])[-10:], threshold=analysis['threshold'] / 100)
    return analysis
