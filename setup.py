from __future__ import annotations

from distutils.errors import DistutilsFileError
import shutil
import subprocess
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py


ROOT = Path(__file__).resolve().parent
FRONTEND_DIR = ROOT / "desktop" / "frontend"
FRONTEND_SOURCE_DIR = ROOT / "desktop" / "frontend" / "dist"
PACKAGE_FRONTEND_DIR = ("sniff4hound", "_frontend_dist")


def _build_frontend_if_needed() -> None:
    if not FRONTEND_DIR.exists():
        raise DistutilsFileError(
            "desktop/frontend/ is missing from the source tree. Rebuild the source distribution "
            "with frontend sources included, or restore desktop/frontend/ before packaging "
            "Sniff4Hound."
        )

    if FRONTEND_SOURCE_DIR.exists():
        output_mtime = max(
            (path.stat().st_mtime for path in FRONTEND_SOURCE_DIR.rglob("*") if path.is_file()),
            default=0,
        )
        source_paths = (
            path
            for path in FRONTEND_DIR.rglob("*")
            if path.is_file()
            and "node_modules" not in path.parts
            and "dist" not in path.parts
        )
        if max((path.stat().st_mtime for path in source_paths), default=0) <= output_mtime:
            return

    npm = shutil.which("npm")
    if npm is None:
        raise DistutilsFileError(
            "desktop/frontend/dist is missing and npm is unavailable. Install Node.js 22 LTS, "
            "then run 'npm ci && npm run build' in desktop/frontend/ before packaging Sniff4Hound."
        )

    try:
        subprocess.run([npm, "ci"], cwd=FRONTEND_DIR, check=True)
        subprocess.run([npm, "run", "build"], cwd=FRONTEND_DIR, check=True)
    except subprocess.CalledProcessError as exc:
        raise DistutilsFileError(
            "Sniff4Hound could not build the frontend automatically. Run 'npm ci && npm run build' "
            "in desktop/frontend/ and try again."
        ) from exc


class build_py(_build_py):
    def _frontend_output_pairs(self) -> list[tuple[str, str]]:
        _build_frontend_if_needed()
        if getattr(self, "editable_mode", False):
            return []
        if not FRONTEND_SOURCE_DIR.exists():
            return []

        target_root = Path(self.build_lib).joinpath(*PACKAGE_FRONTEND_DIR)
        pairs: list[tuple[str, str]] = []
        for source in FRONTEND_SOURCE_DIR.rglob("*"):
            if not source.is_file():
                continue
            target = target_root / source.relative_to(FRONTEND_SOURCE_DIR)
            pairs.append((str(target), str(source)))
        return pairs

    def build_package_data(self) -> None:
        super().build_package_data()

        for target, source in self._frontend_output_pairs():
            target_path = Path(target)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            self.copy_file(source, target)

    def get_output_mapping(self) -> dict[str, str]:
        mapping = super().get_output_mapping()
        for target, source in self._frontend_output_pairs():
            mapping[target] = source
        return mapping


setup(cmdclass={"build_py": build_py})
