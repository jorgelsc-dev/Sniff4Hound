from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_ROOT / "data"


def ensure_data_dir() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR


def resolve_data_file(filename: str) -> Path:
    ensure_data_dir()
    return DATA_DIR / filename


def resolve_repo_file(*parts: str) -> Path:
    return PROJECT_ROOT.joinpath(*parts)

