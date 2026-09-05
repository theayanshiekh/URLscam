"""String similarity helpers for typosquatting detection."""

from __future__ import annotations

import unicodedata


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            ins = curr[j - 1] + 1
            delete = prev[j] + 1
            sub = prev[j - 1] + (ca != cb)
            curr.append(min(ins, delete, sub))
        prev = curr
    return prev[-1]


def normalized_distance(a: str, b: str) -> float:
    if not a and not b:
        return 0.0
    dist = levenshtein(a, b)
    return dist / max(len(a), len(b))


def strip_confusables(value: str) -> str:
    return value.lower().translate(
        str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
    )


def scripts_in(text: str) -> set[str]:
    found: set[str] = set()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        script = name.split(" ")[0]
        if script in {"LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "ARABIC", "DEVANAGARI", "CJK", "HIRAGANA", "KATAKANA", "HANGUL", "HEBREW"}:
            found.add(script)
        elif "CYRILLIC" in name:
            found.add("CYRILLIC")
        elif "GREEK" in name:
            found.add("GREEK")
    return found
