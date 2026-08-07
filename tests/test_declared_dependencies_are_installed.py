"""The environment running the suite must satisfy the pins the package declares.

2026-08-06, found while releasing 0.1.23. The PUBLIC repo — the one that publishes to PyPI — had
`mcp 1.28.1` installed against its own `mcp>=2,<3` pin, and no `httpx2` at all. Twelve tests in
`test_mcp_server.py` had been erroring there with
`TypeError: Server.__init__() got an unexpected keyword argument 'on_list_tools'`, which is what a
v1 SDK says when handed the v2 API. Installing the declared pins turned 1 failed / 400 passed /
12 errors into 417 passed.

Nothing was wrong with the code. What was wrong is that **the shipped MCP-server path was not being
tested in the repo that publishes it**, and the only signal was a wall of errors that read like a
product defect. A dozen red tests are easy to walk past when they have been red for a while; a
single test that names the package, the installed version and the required specifier is not.

This is the "test the artefact, not the sources" lesson pointed at the environment instead: a suite
is only evidence about the product if it runs against the versions the product declares.

Deliberately covers runtime `[project].dependencies` only. Optional groups are not required for the
product to work, and demanding them would make a lean CI box fail for no user-visible reason.
"""
from __future__ import annotations

import importlib.metadata as md
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]

try:                                              # 3.11+
    import tomllib
except ModuleNotFoundError:                       # pragma: no cover - 3.10 and older
    import tomli as tomllib                       # type: ignore[no-redef]


def _runtime_requirements() -> list[Requirement]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    out = []
    for raw in data.get("project", {}).get("dependencies", []):
        req = Requirement(raw)
        # A marker that does not apply to this interpreter is not a pin we are failing to meet.
        if req.marker is not None and not req.marker.evaluate():
            continue
        out.append(req)
    return out


REQUIREMENTS = _runtime_requirements()


def test_the_pyproject_actually_declares_dependencies():
    """Pins the premise. If dependencies moved or were emptied, the parametrised test below would
    silently pass on nothing at all — which is the failure mode it exists to prevent."""
    assert REQUIREMENTS, "no runtime dependencies parsed from pyproject.toml — this check is blind"


@pytest.mark.parametrize("req", REQUIREMENTS, ids=lambda r: r.name)
def test_the_installed_version_satisfies_the_declared_pin(req: Requirement):
    try:
        installed = md.version(req.name)
    except md.PackageNotFoundError:
        pytest.fail(
            f"`{req.name}` is DECLARED as a runtime dependency ({req}) but is not installed in the "
            f"environment running this suite. Every result here is evidence about a different "
            f"product than the one that ships. Install the declared pins and re-run.")

    try:
        version = Version(installed)
    except InvalidVersion:                        # a local/dev build string — not ours to police
        return

    assert req.specifier.contains(version, prereleases=True), (
        f"`{req.name}` {installed} is installed, but this package declares `{req}`. The suite is "
        f"running against a version the product does not support, so a pass here does not mean the "
        f"shipped path works — this exact mismatch (mcp 1.x against `mcp>=2,<3`) hid twelve errors "
        f"in the repo that publishes to PyPI.")
