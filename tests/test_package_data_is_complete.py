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


def _glob_matches(pattern: str, rel: str) -> bool:
    """Setuptools' package-data glob semantics, not fnmatch's.

    ``*`` stays within one path segment and, like ``glob``, does not match a
    leading dot; ``**`` spans zero or more segments, none hidden. ``fnmatch``
    lets ``*`` cross ``/``, which made ``rules_data/*.json`` "cover"
    ``rules_data/v2/x.json`` -- a file the wheel leaves out.
    """
    pats, parts = pattern.split("/"), rel.split("/")

    def seg(p: str, name: str) -> bool:
        return fnmatch.fnmatchcase(name, p) and not (name.startswith(".") and not p.startswith("."))

    def walk(i: int, j: int) -> bool:
        if i == len(pats):
            return j == len(parts)
        if pats[i] == "**":
            return any(
                walk(i + 1, k)
                for k in range(j, len(parts) + 1)
                if all(not x.startswith(".") for x in parts[j:k])
            )
        return j < len(parts) and seg(pats[i], parts[j]) and walk(i + 1, j + 1)

    return walk(0, 0)


def test_the_glob_semantics_are_setuptools() -> None:
    assert _glob_matches("rules_data/*.json", "rules_data/a.json")
    assert not _glob_matches("rules_data/*.json", "rules_data/v2/a.json")
    assert _glob_matches("static/**/*", "static/css/app.css")
    assert _glob_matches("static/**/*", "static/app.css")
    assert not _glob_matches("static/**/*", "static/.well-known/security.txt")
    assert _glob_matches("bundled/*/pack.json", "bundled/x/pack.json")
    assert not _glob_matches("bundled/*/pack.json", "bundled/x/y/pack.json")


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
        if not any(_glob_matches(g, rel) for g in patterns.get(package, [])):
            missing.append(f"{package}: {rel}")
    assert checked > 20, "the walk found almost no data files; it proves nothing"
    assert missing == [], f"not in [tool.setuptools.package-data]: {missing}"
