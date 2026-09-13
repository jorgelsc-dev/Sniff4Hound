from __future__ import annotations

import re
from typing import Any

from . import settings

try:  # pragma: no cover - exercised when the optional dependency is absent.
    import regex as _timeout_regex
except Exception:  # pragma: no cover
    _timeout_regex = None


_COMPILED_REGEX_CACHE: dict[tuple[str, int, bool], Any | None] = {}


def limit_regex_subject(value: Any) -> str:
    """Bound attacker-controlled text before any capture-path regex search."""
    text = str(value or "")
    limit = max(1, int(settings.PAYLOAD_TEXT_MAX_CHARS))
    return text[:limit] if len(text) > limit else text


def regex_has_backtracking_risk(pattern: str) -> bool:
    """Cheap guardrail for user-defined regexes on the capture path."""
    pattern = str(pattern or "")
    if re.search(r"\\[1-9]", pattern):
        return True
    for group in re.findall(r"\(([^()]*)\)\s*(?:[+*]|\{\d+,?\d*\})", pattern):
        has_inner_repeat = re.search(r"(?:\.\*|\.\+|\\[dwsDWS][+*]|\[[^\]]+\][+*]|[A-Za-z0-9][+*])", group)
        has_literal_separator = re.search(r"(?:\\[./:_-]|[./:_-])", group)
        if has_inner_repeat and not has_literal_separator:
            return True
    if re.search(r"\.\*\s*(?:\.\*|\{)", pattern):
        return True
    if re.search(r"\([^)]*\|[^)]*\)\s*(?:[+*]|\{\d+,?\d*\})", pattern):
        alternatives = re.findall(r"\(([^)]*\|[^)]*)\)\s*(?:[+*]|\{\d+,?\d*\})", pattern)
        for group in alternatives:
            parts = [part.strip("\\^$") for part in group.split("|") if part]
            if any(left and right and (left.startswith(right) or right.startswith(left)) for left in parts for right in parts if left != right):
                return True
    return False


def validate_regex_pattern(pattern: str, *, max_length: int | None = None) -> str:
    text = str(pattern or "").strip()
    if not text:
        raise ValueError("Regex pattern is required")
    limit = int(max_length or settings.MONITOR_MAX_REGEX_LENGTH)
    if len(text) > limit:
        raise ValueError(f"Regex pattern is too long (max {limit} characters)")
    try:
        re.compile(text)
    except re.error as exc:
        raise ValueError(f"Invalid regex pattern '{text}': {exc}") from exc
    if regex_has_backtracking_risk(text):
        raise ValueError(f"Regex pattern has nested or ambiguous repetition risk: '{text}'")
    return text


def compiled_regex(pattern: str, flags: int = re.IGNORECASE):
    text = str(pattern or "").strip()
    key = (text, int(flags), _timeout_regex is not None)
    if key in _COMPILED_REGEX_CACHE:
        return _COMPILED_REGEX_CACHE[key]
    try:
        if _timeout_regex is not None:
            compiled = _timeout_regex.compile(text, flags)
        else:
            compiled = re.compile(text, flags)
    except Exception:
        compiled = None
    _COMPILED_REGEX_CACHE[key] = compiled
    return compiled


def regex_search(compiled, value: Any):
    if compiled is None:
        return None
    subject = limit_regex_subject(value)
    try:
        if _timeout_regex is not None:
            return compiled.search(subject, timeout=settings.MONITOR_REGEX_TIMEOUT_SECONDS)
        return compiled.search(subject)
    except TimeoutError:
        return None
    except Exception:
        return None
