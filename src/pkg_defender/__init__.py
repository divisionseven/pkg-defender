"""pkg-defender — supply chain attack defense CLI."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as get_version

try:
    __version__ = get_version("pkg-defender")
except PackageNotFoundError:
    # Fallback for development: read directly from pyproject.toml
    import tomllib
    from pathlib import Path

    pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
    try:
        with open(pyproject_path, "rb") as f:
            __version__ = tomllib.load(f)["project"]["version"]
    except Exception:
        __version__ = "1.0.0"
