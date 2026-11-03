"""
One-time helper: creates the full project folder structure.
Run it from inside the soc_log_analyzer/ folder:  python setup_structure.py
Safe to run multiple times (it never deletes or overwrites anything).
"""
from pathlib import Path

BASE = Path(__file__).resolve().parent

# Folders that are Python packages (need __init__.py)
PACKAGES = ["database", "parser", "detection", "ml", "analysis", "generators", "tests",
            "services", "routes"]

# Other folders
FOLDERS = [
    "templates",
    "static/css",
    "static/js",
    "data",
    "data/uploads",
    "reports",
]


def main():
    for pkg in PACKAGES:
        folder = BASE / pkg
        folder.mkdir(parents=True, exist_ok=True)
        init_file = folder / "__init__.py"
        if not init_file.exists():
            init_file.touch()
        print(f"[ok] package: {pkg}/")

    for name in FOLDERS:
        folder = BASE / name
        folder.mkdir(parents=True, exist_ok=True)
        # .gitkeep keeps empty folders when using Git
        keep = folder / ".gitkeep"
        if not keep.exists():
            keep.touch()
        print(f"[ok] folder:  {name}/")

    print("\nProject structure is ready.")


if __name__ == "__main__":
    main()