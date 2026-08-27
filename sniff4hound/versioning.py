from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path


SEMVER_RE = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")
TAG_SEMVER_RE = re.compile(r"^v(?P<version>\d+\.\d+\.\d+)$")
PROJECT_VERSION_RE = re.compile(r'(?m)^version = "(?P<version>\d+\.\d+\.\d+)"$')
INIT_VERSION_RE = re.compile(r'(?m)^__version__ = "(?P<version>\d+\.\d+\.\d+)"$')
BREAKING_RE = re.compile(r"(^|\n)BREAKING CHANGE\b|^[a-z]+(?:\(.+\))?!:", re.IGNORECASE | re.MULTILINE)
CONVENTIONAL_RE = re.compile(r"^(?P<kind>[a-z]+)(?:\(.+\))?(?P<breaking>!)?:", re.IGNORECASE)

PATCH_LIKE_KINDS = {
    "build",
    "chore",
    "ci",
    "doc",
    "docs",
    "fix",
    "merge",
    "optimo",
    "perf",
    "refactor",
    "style",
    "test",
    "tests",
}
FEATURE_LIKE_KINDS = {
    "add",
    "feat",
    "feature",
    "implement",
    "radar",
    "ui",
    "ux",
}


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    def bump(self, level: str) -> "Version":
        normalized = str(level or "").strip().lower()
        if normalized == "major":
            return Version(self.major + 1, 0, 0)
        if normalized == "minor":
            return Version(self.major, self.minor + 1, 0)
        if normalized == "patch":
            return Version(self.major, self.minor, self.patch + 1)
        return self

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class CommitChange:
    sha: str
    subject: str
    body: str
    kind: str
    files: tuple[str, ...]
    total_lines: int
    weighted_score: float
    categories: tuple[str, ...]


@dataclass(frozen=True)
class VersionDecision:
    current_version: str
    base_version: str
    next_version: str
    bump: str
    anchor_tag: str
    anchor_version: str
    commit_count: int
    total_lines: int
    weighted_score: float
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "current_version": self.current_version,
            "base_version": self.base_version,
            "next_version": self.next_version,
            "bump": self.bump,
            "anchor_tag": self.anchor_tag,
            "anchor_version": self.anchor_version,
            "commit_count": self.commit_count,
            "total_lines": self.total_lines,
            "weighted_score": round(self.weighted_score, 2),
            "reasons": list(self.reasons),
        }


def parse_version(value: str) -> Version:
    text = str(value or "").strip()
    match = SEMVER_RE.fullmatch(text)
    if not match:
        raise ValueError(f"Invalid semantic version: {value!r}")
    return Version(
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
    )


def _run_git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def _git_available(root: Path) -> bool:
    try:
        _run_git(root, "rev-parse", "--is-inside-work-tree")
    except Exception:
        return False
    return True


def read_project_version(root: Path) -> str:
    pyproject_path = root / "pyproject.toml"
    match = PROJECT_VERSION_RE.search(pyproject_path.read_text(encoding="utf-8"))
    if not match:
        raise ValueError(f"Unable to locate [project].version in {pyproject_path}")
    return match.group("version")


def read_init_version(root: Path) -> str:
    init_path = root / "sniff4hound" / "__init__.py"
    match = INIT_VERSION_RE.search(init_path.read_text(encoding="utf-8"))
    if not match:
        raise ValueError(f"Unable to locate __version__ in {init_path}")
    return match.group("version")


def read_version_from_ref(root: Path, ref: str) -> str:
    if not str(ref or "").strip():
        return ""
    for relative_path, pattern in (
        ("pyproject.toml", PROJECT_VERSION_RE),
        ("sniff4hound/__init__.py", INIT_VERSION_RE),
    ):
        try:
            text = _run_git(root, "show", f"{ref}:{relative_path}")
        except subprocess.CalledProcessError:
            continue
        match = pattern.search(text)
        if match:
            return match.group("version")
    return ""


def _path_category(path: str) -> str:
    normalized = str(path or "").strip().replace("\\", "/")
    if not normalized:
        return "other"
    if normalized.startswith("sniff4hound/") and normalized.endswith(".py"):
        return "core"
    if normalized.startswith("frontend/src/state/"):
        return "frontend-state"
    if normalized.startswith("frontend/src/views/"):
        return "frontend-view"
    if normalized.startswith("frontend/src/components/"):
        return "frontend-component"
    if normalized.startswith("frontend/src/"):
        return "frontend"
    if normalized.startswith(".github/workflows/") or normalized.startswith("scripts/"):
        return "build"
    if normalized.startswith("tests/"):
        return "test"
    if normalized.startswith("docs/") or normalized.endswith(".md"):
        return "docs"
    return "other"


def _path_weight(path: str) -> float:
    category = _path_category(path)
    if category == "core":
        return 5.0
    if category == "frontend-state":
        return 4.2
    if category == "frontend-view":
        return 3.9
    if category == "frontend-component":
        return 3.5
    if category == "frontend":
        return 3.1
    if category == "build":
        return 2.7
    if category == "test":
        return 1.8
    if category == "docs":
        return 1.0
    return 2.2


def _commit_kind(subject: str) -> str:
    text = str(subject or "").strip()
    if not text:
        return "other"
    match = CONVENTIONAL_RE.match(text)
    if match:
        return match.group("kind").lower()
    lowered = text.lower()
    if lowered.startswith("merge "):
        return "merge"
    token = re.split(r"[\s:/-]+", lowered, maxsplit=1)[0]
    return token or "other"


def _iter_tags(root: Path) -> list[str]:
    output = _run_git(root, "tag", "--list", "--sort=-creatordate")
    return [line.strip() for line in output.splitlines() if line.strip()]


def resolve_anchor_tag(root: Path) -> tuple[str, str]:
    semver_tags = []
    marker_tags = []
    for tag in _iter_tags(root):
        semver_match = TAG_SEMVER_RE.fullmatch(tag)
        if semver_match:
            semver_tags.append((tag, semver_match.group("version")))
            continue
        if tag.startswith("main-"):
            marker_tags.append(tag)
    if semver_tags:
        return semver_tags[0]
    if marker_tags:
        return marker_tags[0], ""
    return "", ""


def collect_commits_since(root: Path, anchor_tag: str = "") -> list[CommitChange]:
    range_spec = f"{anchor_tag}..HEAD" if anchor_tag else "HEAD"
    output = _run_git(root, "log", "--reverse", "--format=%x1e%H%x1f%s%x1f%b", "--numstat", range_spec)
    commits: list[CommitChange] = []
    for raw_record in output.split("\x1e"):
        record = raw_record.strip()
        if not record:
            continue
        lines = record.splitlines()
        if not lines:
            continue
        meta = lines[0].split("\x1f", 2)
        sha = meta[0].strip() if meta else ""
        subject = meta[1].strip() if len(meta) > 1 else ""
        body = meta[2].strip() if len(meta) > 2 else ""
        files = []
        total_lines = 0
        weighted_score = 0.0
        categories = set()
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            added = 0 if parts[0] == "-" else int(parts[0] or 0)
            deleted = 0 if parts[1] == "-" else int(parts[1] or 0)
            path = parts[2].strip()
            files.append(path)
            changed_lines = added + deleted
            if changed_lines <= 0:
                changed_lines = 1
            total_lines += changed_lines
            weighted_score += changed_lines * _path_weight(path)
            categories.add(_path_category(path))
        commits.append(
            CommitChange(
                sha=sha,
                subject=subject,
                body=body,
                kind=_commit_kind(subject),
                files=tuple(files),
                total_lines=total_lines,
                weighted_score=weighted_score,
                categories=tuple(sorted(categories)),
            )
        )
    return commits


def decide_bump(commits: list[CommitChange]) -> tuple[str, tuple[str, ...]]:
    if not commits:
        return "none", ("No commits detected after the last release marker.",)

    total_weight = sum(item.weighted_score for item in commits)
    total_lines = sum(item.total_lines for item in commits)
    patch_like = all(item.kind in PATCH_LIKE_KINDS for item in commits)
    feature_like = any(item.kind in FEATURE_LIKE_KINDS for item in commits)
    breaking = any(BREAKING_RE.search(f"{item.subject}\n{item.body}".strip()) for item in commits)
    core_heavy = any("core" in item.categories and item.weighted_score >= 90 for item in commits)
    frontend_surface = any(
        ("frontend-view" in item.categories or "frontend-component" in item.categories or "frontend-state" in item.categories)
        and item.weighted_score >= 60
        for item in commits
    )
    spread = len({category for item in commits for category in item.categories})
    reasons = [
        f"Analyzed {len(commits)} commit(s), {total_lines} changed lines, weighted score {total_weight:.1f}.",
    ]

    if breaking:
        reasons.append("Found an explicit breaking-change marker in Git history.")
        return "major", tuple(reasons)

    if feature_like:
        reasons.append("Detected feature-style commit subjects in the pending release window.")
        return "minor", tuple(reasons)

    if not patch_like and (core_heavy or frontend_surface or total_weight >= 160 or spread >= 3):
        if core_heavy:
            reasons.append("Core runtime files crossed the heavy-change threshold.")
        if frontend_surface:
            reasons.append("Frontend views/components carried a high-impact UI surface change.")
        if total_weight >= 160:
            reasons.append("The aggregate weighted score crossed the minor-release threshold.")
        return "minor", tuple(reasons)

    reasons.append("Changes remain within patch scope, so only the patch number advances.")
    return "patch", tuple(reasons)


def resolve_version(root: Path) -> VersionDecision:
    current_version = read_project_version(root)
    init_version = read_init_version(root)
    if current_version != init_version:
        raise ValueError(
            f"Version mismatch between pyproject.toml ({current_version}) and sniff4hound/__init__.py ({init_version})"
        )

    if not _git_available(root):
        return VersionDecision(
            current_version=current_version,
            base_version=current_version,
            next_version=current_version,
            bump="none",
            anchor_tag="",
            anchor_version="",
            commit_count=0,
            total_lines=0,
            weighted_score=0.0,
            reasons=("Git metadata is unavailable, keeping the current version untouched.",),
        )

    anchor_tag, anchor_version = resolve_anchor_tag(root)
    anchor_file_version = read_version_from_ref(root, anchor_tag) if anchor_tag else ""
    commits = collect_commits_since(root, anchor_tag=anchor_tag)
    bump, reasons = decide_bump(commits)
    base_version = anchor_version or anchor_file_version or current_version
    base = parse_version(base_version)
    next_version = str(base.bump(bump))
    if bump == "none":
        next_version = base_version
    current = parse_version(current_version)
    candidate = parse_version(next_version)
    if current > candidate:
        reasons = reasons + (
            "Current working-tree version already meets or exceeds the computed release version.",
        )
        next_version = current_version
    return VersionDecision(
        current_version=current_version,
        base_version=base_version,
        next_version=next_version,
        bump=bump,
        anchor_tag=anchor_tag,
        anchor_version=anchor_version,
        commit_count=len(commits),
        total_lines=sum(item.total_lines for item in commits),
        weighted_score=sum(item.weighted_score for item in commits),
        reasons=reasons,
    )


def write_version(root: Path, version: str) -> None:
    normalized = str(parse_version(version))
    pyproject_path = root / "pyproject.toml"
    init_path = root / "sniff4hound" / "__init__.py"

    pyproject_text = pyproject_path.read_text(encoding="utf-8")
    init_text = init_path.read_text(encoding="utf-8")

    pyproject_updated, pyproject_count = PROJECT_VERSION_RE.subn(f'version = "{normalized}"', pyproject_text, count=1)
    init_updated, init_count = INIT_VERSION_RE.subn(f'__version__ = "{normalized}"', init_text, count=1)

    if pyproject_count != 1:
        raise ValueError(f"Unable to update project version in {pyproject_path}")
    if init_count != 1:
        raise ValueError(f"Unable to update __version__ in {init_path}")

    pyproject_path.write_text(pyproject_updated, encoding="utf-8")
    init_path.write_text(init_updated, encoding="utf-8")


def apply_resolved_version(root: Path) -> VersionDecision:
    decision = resolve_version(root)
    if decision.current_version != decision.next_version:
        write_version(root, decision.next_version)
    return replace(decision, current_version=decision.next_version)


def decision_json(root: Path, *, apply: bool = False) -> str:
    decision = apply_resolved_version(root) if apply else resolve_version(root)
    return json.dumps(decision.to_dict(), ensure_ascii=False, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Resolve and optionally apply the next Sniff4Hound semantic version from Git history."
    )
    parser.add_argument(
        "--root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Repository root that contains pyproject.toml.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write the resolved version into pyproject.toml and sniff4hound/__init__.py.",
    )
    parser.add_argument(
        "--print-version",
        action="store_true",
        help="Print only the resolved semantic version.",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    decision = apply_resolved_version(root) if args.apply else resolve_version(root)
    if args.print_version:
        print(decision.next_version)
        return 0
    print(json.dumps(decision.to_dict(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
