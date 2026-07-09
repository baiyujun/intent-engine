"""Tests for tier0.text_preprocess — standalone extraction of ClawSentry text_utils.

Covers:
- normalize_text strips zero-width space (U+200B)
- normalize_text strips combining diacritical mark (U+0300)
- normalize_text preserves emoji U+FE0F (NOT stripped)
- count_invisible_chars returns correct count for known invisible chars
- normalize_text on empty string returns empty string
- normalize_text on pure ASCII returns unchanged
- INVISIBLE_CODEPOINTS excludes U+FE0F and INVISIBLE_RE strips invisibles
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure repo root is importable when running from anywhere
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tier0.text_preprocess import (
    INVISIBLE_CODEPOINTS,
    INVISIBLE_RE,
    count_invisible_chars,
    normalize_text,
)


# ---------------------------------------------------------------------------
# normalize_text
# ---------------------------------------------------------------------------

class TestNormalizeText:
    def test_strips_zero_width_space(self):
        # U+200B is an invisible zero-width space between two visible words
        assert normalize_text("Hello​World") == "HelloWorld"

    def test_strips_combining_accent(self):
        # 'i' + U+0300 (COMBINING GRAVE ACCENT, category Mn) should collapse
        # the accent away, leaving 'ignore'
        assert normalize_text("ig̀nore") == "ignore"

    def test_preserves_emoji_variation_selector(self):
        # U+FE0F (VS-16) is used for emoji presentation (❤️ = U+2764 U+FE0F).
        # It must NOT be stripped, otherwise the emoji is corrupted.
        normalized = normalize_text("❤️")
        assert normalized == "❤️"
        # Explicit code-point check: both the heart and VS-16 survive
        assert [ord(c) for c in normalized] == [0x2764, 0xFE0F]

    def test_empty_string_returns_empty(self):
        assert normalize_text("") == ""

    def test_pure_ascii_unchanged(self):
        text = "Hello World 123"
        assert normalize_text(text) == text

    def test_nfkc_fullwidth_collapses(self):
        # NFKC should collapse fullwidth Latin letters to ASCII
        fullwidth = "Ｈｅｌｌｏ"  # U+FF28 U+FF45 U+FF4C U+FF4C U+FF4F
        assert normalize_text(fullwidth) == "Hello"


# ---------------------------------------------------------------------------
# count_invisible_chars
# ---------------------------------------------------------------------------

class TestCountInvisibleChars:
    def test_known_invisible_count(self):
        # U+200B (ZWSP) + U+200D (ZWJ) + U+FEFF (BOM/ZWNBSP) are all invisible
        text = "a​b‍c﻿d"
        assert count_invisible_chars(text) == 3

    def test_no_invisible_chars(self):
        assert count_invisible_chars("plain ASCII text") == 0

    def test_empty_string(self):
        assert count_invisible_chars("") == 0

    def test_fe0f_not_counted_as_invisible(self):
        # U+FE0F is excluded from INVISIBLE_CODEPOINTS, so it is not counted
        assert count_invisible_chars("❤️") == 0

    def test_count_matches_regex_strip_length(self):
        # The number of invisible chars counted should equal the number of
        # chars removed by INVISIBLE_RE (a cross-check between the two APIs).
        text = "x​y‪czFw"
        counted = count_invisible_chars(text)
        stripped = INVISIBLE_RE.sub("", text)
        assert counted == len(text) - len(stripped)


# ---------------------------------------------------------------------------
# Registry invariants
# ---------------------------------------------------------------------------

class TestInvisibleRegistry:
    def test_fe0f_excluded(self):
        assert 0xFE0F not in INVISIBLE_CODEPOINTS

    def test_fe00_through_fe0e_included(self):
        for cp in range(0xFE00, 0xFE0E + 1):
            assert cp in INVISIBLE_CODEPOINTS

    def test_nonempty(self):
        # The ClawSentry registry has ~390 code points; sanity floor
        assert len(INVISIBLE_CODEPOINTS) > 300
