"""Runs every test_* function in this folder without needing pytest:  python tests/run_all.py
(With pytest installed, `pytest tests` works too.)"""
import importlib.util
import sys
import traceback
from pathlib import Path

here = Path(__file__).resolve().parent
passed = failed = 0
for path in sorted(here.glob("test_*.py")):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name in sorted(n for n in dir(mod) if n.startswith("test_")):
        try:
            getattr(mod, name)()
            passed += 1
            print("ok   ", path.name, name)
        except Exception:  # noqa: BLE001 - report every failure, keep going
            failed += 1
            print("FAIL ", path.name, name)
            traceback.print_exc()
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
