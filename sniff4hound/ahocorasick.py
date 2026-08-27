"""Minimal pure-Python Aho-Corasick multi-pattern matcher.

Exists so `sniff4hound.monitors.evaluate_packet` can check tens of thousands
of `payload_contains` literals against one packet's text in a single pass
over that text, instead of one `needle in haystack` scan per monitor - the
same reason production-grade IDS engines use a multi-pattern matcher for
their "fast pattern" content keyword. No third-party dependency (see
CLAUDE.md's near-zero-dependency policy) - this is a straightforward,
well-known construction: a trie of the patterns plus failure links so a
mismatch resumes from the longest matching suffix instead of restarting.

Only presence ("which of these patterns occur anywhere in this text") is
needed here, not positions, so `search` returns a set of matched pattern
strings.
"""

from __future__ import annotations

from collections import deque


class _Node:
    __slots__ = ("children", "fail", "output")

    def __init__(self) -> None:
        self.children: dict[str, "_Node"] = {}
        self.fail: "_Node" = self
        self.output: frozenset[str] = frozenset()


class AhoCorasick:
    """Build once from a fixed set of patterns, then call `search()` (or
    `contains_any()`) as many times as needed - construction is the
    expensive part (O(total pattern length) with a BFS to link failure
    edges), searching is O(len(text)) regardless of how many patterns were
    given, plus O(number of matches) to collect output."""

    def __init__(self, patterns) -> None:
        self._root = _Node()
        distinct = {str(pattern) for pattern in patterns if pattern}
        for pattern in distinct:
            self._insert(pattern)
        self._build_fail_links()
        self.pattern_count = len(distinct)

    def _insert(self, pattern: str) -> None:
        node = self._root
        for char in pattern:
            child = node.children.get(char)
            if child is None:
                child = _Node()
                node.children[char] = child
            node = child
        node.output = node.output | {pattern}

    def _build_fail_links(self) -> None:
        queue: deque[_Node] = deque()
        for child in self._root.children.values():
            child.fail = self._root
            queue.append(child)

        while queue:
            current = queue.popleft()
            for char, child in current.children.items():
                queue.append(child)
                fail = current.fail
                while fail is not self._root and char not in fail.children:
                    fail = fail.fail
                child.fail = fail.children.get(char, self._root)
                # A node's full output is its own terminal pattern(s) plus
                # everything reachable via its fail link (every pattern that
                # is a suffix of the string spelled out by this node) -
                # merge here once at build time so `search()` can just read
                # `node.output` directly instead of walking fail links.
                child.output = child.output | child.fail.output

    def search(self, text: str) -> set[str]:
        """Every distinct pattern that occurs anywhere in `text`."""
        if not self.pattern_count or not text:
            return set()
        node = self._root
        matches: set[str] = set()
        for char in text:
            while node is not self._root and char not in node.children:
                node = node.fail
            node = node.children.get(char, self._root)
            if node.output:
                matches |= node.output
        return matches

    def contains_any(self, text: str) -> bool:
        if not self.pattern_count or not text:
            return False
        node = self._root
        for char in text:
            while node is not self._root and char not in node.children:
                node = node.fail
            node = node.children.get(char, self._root)
            if node.output:
                return True
        return False
