#!/usr/bin/env python3
"""Translate the whole page into languages and save frontend/lang/<code>.json (then the site needs no AI at run time).
Usage:  GEMINI_API_KEY=... python3 tools/build_lang.py hi te ur      (or:  --all)
Safe to stop and run again: it continues where it stopped."""
import json, os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
import translate

key = os.getenv("GEMINI_API_KEY")
if not key:
    sys.exit("Set GEMINI_API_KEY first.")
codes = [c for c in translate.LANGS] if "--all" in sys.argv else [c for c in sys.argv[1:] if c in translate.LANGS]
if not codes:
    sys.exit("Give language codes, e.g. hi te ur, or --all")
master = translate.master()
os.makedirs(translate.LANG_DIR, exist_ok=True)
for code in codes:
    path = os.path.join(translate.LANG_DIR, code + ".json")
    have = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else {}
    bad = 0
    while True:
        todo = [i for i in master if i not in have]
        if not todo or bad >= 3:
            break
        while (w := translate.pace.take()) != 0:
            if w < 0:
                json.dump(have, open(path, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
                sys.exit("Daily Gemini allowance used up. Run again tomorrow.")
            time.sleep(min(w, 20))
        new = translate.translate_batch(code, {i: master[i] for i in todo[:translate.BATCH]}, key)
        bad = 0 if new else bad + 1
        have.update(new)
        json.dump(have, open(path, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
        print(f"{code}: {len(have)}/{len(master)}", flush=True)
