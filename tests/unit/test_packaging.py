import tomllib
from pathlib import Path


def test_pyproject_dependencies_declared():
    repo_root = Path(__file__).resolve().parents[2]
    with open(repo_root / "pyproject.toml", "rb") as f:
        data = tomllib.load(f)

    deps = data.get("project", {}).get("dependencies", [])
    assert deps, "pyproject.toml must declare dependencies"
    dep_names = [d.split(">=")[0].split("==")[0].strip() for d in deps]
    assert "python-libnmap" in dep_names
    assert "aiohttp" in dep_names
    assert "groq" in dep_names
    assert "python-dotenv" in dep_names
