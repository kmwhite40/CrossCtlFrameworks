"""Every data file the code reads ships in the wheel the Docker image installs.

The image does a non-editable ``pip install``, so ``/app/src`` is never on the
path: a data file not listed in ``[tool.setuptools.package-data]`` simply does
not exist at runtime. The suite runs on an editable install and cannot notice.
``fedramp20x/marketplace_data/`` was missed exactly this way -- in the image,
``ccf sources-seed`` raised FileNotFoundError and rolled back every source's
registration, and the Marketplace could never refresh.
"""

from __future__ import annotations

import fnmatch
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
_CODE = {".py", ".pyc", ".pyi", ".typed"}


def _package_data() -> dict[str, list[str]]:
    doc = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    data: dict[str, list[str]] = doc["tool"]["setuptools"]["package-data"]
    return data


def _owning_package(path: Path) -> tuple[str, Path]:
    d = path.parent
    while not (d / "__init__.py").exists():
        d = d.parent
    return ".".join(d.relative_to(SRC).parts), d


def test_every_data_file_under_src_is_packaged() -> None:
    patterns = _package_data()
    missing: list[str] = []
    checked = 0
    for path in (SRC / "ccf").rglob("*"):
        if (
            not path.is_file()
            or path.suffix in _CODE
            or "__pycache__" in path.parts
            or path.name.startswith(".")
        ):
            continue
        checked += 1
        package, pkg_dir = _owning_package(path)
        rel = path.relative_to(pkg_dir).as_posix()
        globs = [g.replace("**/", "*").replace("**", "*") for g in patterns.get(package, [])]
        if not any(fnmatch.fnmatch(rel, g) for g in globs):
            missing.append(f"{package}: {rel}")
    assert checked > 20, "the walk found almost no data files; it proves nothing"
    assert missing == [], f"not in [tool.setuptools.package-data]: {missing}"
