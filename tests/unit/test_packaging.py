from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        tomllib = None


def test_pyproject_dependencies_declared():
    repo_root = Path(__file__).resolve().parents[2]
    pyproject_path = repo_root / "pyproject.toml"

    if tomllib is not None:
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
        deps = data.get("project", {}).get("dependencies", [])
    else:
        # Fallback parser for Python 3.10 environments without tomli
        content = pyproject_path.read_text(encoding="utf-8")
        deps = [line.strip().strip('"').strip("',") for line in content.splitlines() if ">=" in line]

    assert deps, "pyproject.toml must declare dependencies"
    dep_names = [d.split(">=")[0].split("==")[0].strip() for d in deps]
    assert "python-libnmap" in dep_names
    assert "aiohttp" in dep_names
    assert "groq" in dep_names
    assert "python-dotenv" in dep_names
