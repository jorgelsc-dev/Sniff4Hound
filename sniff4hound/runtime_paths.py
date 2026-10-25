from __future__ import annotations

from pathlib import Path

from .settings import DATA_DIR as CONFIGURED_DATA_DIR


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = Path(__file__).resolve().parent
DATA_DIR = CONFIGURED_DATA_DIR
BUNDLED_DATA_DIR = PACKAGE_ROOT / "data"


def ensure_data_dir() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR


def resolve_data_file(filename: str) -> Path:
    ensure_data_dir()
    candidate = Path(str(filename or "")).name
    if not candidate:
        raise ValueError("filename is required")
    return DATA_DIR / candidate


def resolve_repo_file(*parts: str) -> Path:
    return PROJECT_ROOT.joinpath(*parts)

