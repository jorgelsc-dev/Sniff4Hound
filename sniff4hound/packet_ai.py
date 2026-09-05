"""Local, transductive LOF over byte-image features; no external services.

Scores describe the current cohort, not attack probabilities. The model is
refitted per bounded snapshot and never treats unlabelled traffic as clean.
"""
import base64
import json
import math
import struct
import zlib
from collections import defaultdict

MAX_BYTES = 4096
MIN_COHORT = 20


def packet_bytes(packet):
    if packet.get("frame_hex"):
        data = bytes.fromhex(packet["frame_hex"][:MAX_BYTES * 2])
        return data, "frame", max(packet.get("frame_length") or 0, packet.get("length") or 0) > len(data)
    raw = packet.get("raw_packet")
    if isinstance(raw, (bytes, bytearray, memoryview)) and raw:
        raw = bytes(raw)
        return raw[:MAX_BYTES], "frame", max(len(raw), packet.get("length") or 0) > MAX_BYTES
    try:
        data = bytes.fromhex(str(packet.get("payload_hex") or "")[:MAX_BYTES * 2])
    except ValueError:
        data = b""
    return data, "payload_preview", True


def image_png(data):
    """One byte per grayscale pixel, 64 columns, zero-padded final row."""
    width = 64
    height = max(1, math.ceil(len(data) / width))
    padded = data.ljust(width * height, b"\0")
    scanlines = b"".join(b"\0" + padded[i:i + width] for i in range(0, len(padded), width))

    def chunk(kind, body):
        return struct.pack("!I", len(body)) + kind + body + struct.pack("!I", zlib.crc32(kind + body))

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack("!IIBBBBB", width, height, 8, 0, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(scanlines)) + chunk(b"IEND", b"")
    return "data:image/png;base64," + base64.b64encode(png).decode("ascii"), height


def image_features(data):
    # Intensity histogram + 8x8 spatial pooling of the displayed image.
    # Padding is excluded so it cannot masquerade as observed zero bytes.
    histogram = [0.0] * 16
    pools = [[] for _ in range(64)]
    height = max(1, math.ceil(len(data) / 64))
    for i, value in enumerate(data):
        histogram[value // 16] += 1 / len(data)
        row, col = divmod(i, 64)
        pools[min(7, row * 8 // height) * 8 + col // 8].append(value / 255)
    return histogram + [sum(pool) / len(pool) if pool else 0.0 for pool in pools]


def lof_scores(vectors, k=10):
    """LOF with fixed k nearest neighbours, excluding each sample itself."""
    n = len(vectors)
    if n < MIN_COHORT:
        return [None] * n
    k = min(k, n - 1)
    distances = [[0.0] * n for _ in vectors]
    for i in range(n):
        for j in range(i):
            distance = math.sqrt(sum((a - b) ** 2 for a, b in zip(vectors[i], vectors[j])))
            distances[i][j] = distances[j][i] = distance
    neighbors = [sorted((j for j in range(n) if j != i), key=lambda j: (distances[i][j], j))[:k] for i in range(n)]
    radii = [distances[i][neighbors[i][-1]] for i in range(n)]
    densities = [k / max(1e-9, sum(max(radii[j], distances[i][j]) for j in neighbors[i])) for i in range(n)]
    return [sum(densities[j] for j in neighbors[i]) / (k * densities[i]) for i in range(n)]


def _json(value, fallback):
    try:
        return json.loads(value) if isinstance(value, str) else value or fallback
    except (ValueError, TypeError):
        return fallback


def analyze_packets(packets, threshold=50):
    rows, groups = [], defaultdict(list)
    for packet in packets:
        data, source, partial = packet_bytes(packet)
        details = _json(packet.get("details_json"), {})
        tags = _json(packet.get("tags_json"), [])
        alerted = bool(_json(packet.get("rule_hits_json"), [])) or any(
            isinstance(tag, dict) and tag.get("key") == "monitor_id" for tag in tags
        )
        detection = details.get("ai_detection_status", "unknown")
        png, height = image_png(data) if data else (None, 0)
        row = {key: packet.get(key) for key in ("id", "proto", "src_ip", "dst_ip", "src_port", "dst_port", "created_at", "length")}
        row.update(image=png, width=64, height=height, byte_count=len(data), partial=partial,
                   source=source, alerted=alerted, detection_status=detection,
                   sampled=bool(details.get("ai_sample")), score=None, lof=None,
                   candidate=False, cohort_size=0, status="insufficient_data" if data else "no_bytes")
        rows.append(row)
        if data:
            groups[(packet.get("proto"), source, partial)].append((row, image_features(data)))
    for group in groups.values():
        factors = lof_scores([features for _, features in group])
        for (row, _), factor in zip(group, factors):
            row["cohort_size"] = len(group)
            if factor is None:
                continue
            score = round(100 * max(0.0, 1 - 1 / max(factor, 1)), 1)
            row.update(score=score, lof=round(factor, 4), status="analyzed",
                       candidate=score >= threshold and not row["alerted"] and row["detection_status"] == "evaluated")
    rows.sort(key=lambda row: (row["score"] is not None, row["score"] or 0, row["id"] or 0), reverse=True)
    return {"model": "byte-image-lof-v1", "threshold": threshold, "minimum_cohort": MIN_COHORT,
            "analyzed": sum(row["score"] is not None for row in rows),
            "candidates": sum(row["candidate"] for row in rows), "rows": rows}
