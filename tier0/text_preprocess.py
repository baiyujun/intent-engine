"""Text preprocessing — standalone extraction of ClawSentry's text_utils.

Faithful re-implementation of ClawSentry gateway/text_utils.py with NO imports
from ClawSentry. Applies:
  1. NFKC normalization (collapses fullwidth/halfwidth compatibility variants)
  2. NFD strip combining marks (Unicode category Mn) EXCEPT U+FE0F (emoji VS-16)
  3. NFC re-compose
  4. Strip invisible Unicode code points (same codepoint ranges as ClawSentry)

Note: U+FE0F (VS-16, emoji variation selector) is intentionally EXCLUDED from
INVISIBLE_CODEPOINTS to avoid corrupting normal emoji text (e.g. ❤️ = U+2764
U+FE0F).
"""

from __future__ import annotations

import re
import unicodedata


# ---------------------------------------------------------------------------
# Invisible Unicode code point registry
# ---------------------------------------------------------------------------

def _build_invisible_codepoints() -> frozenset[int]:
    """Build the set of invisible Unicode code points.

    Mirrors ClawSentry text_utils._build_invisible_codepoints exactly.
    U+FE0F (VS-16, emoji variation selector) is intentionally EXCLUDED to avoid
    corrupting normal emoji text (e.g. ❤️ = U+2764 U+FE0F).
    """
    cps: set[int] = set()

    # Zero-width characters (U+200B–U+200F)
    cps.update(range(0x200B, 0x200F + 1))

    # Bidi embedding/override characters (U+202A–U+202E)
    cps.update(range(0x202A, 0x202E + 1))

    # Word joiner + invisible math operators (U+2060–U+2065)
    cps.update(range(0x2060, 0x2065 + 1))

    # Bidi isolates (U+2066–U+2069)
    cps.update(range(0x2066, 0x2069 + 1))

    # Deprecated formatting controls (U+206A–U+206F)
    cps.update(range(0x206A, 0x206F + 1))

    # Mongolian free variation selectors (U+180B–U+180F)
    cps.update(range(0x180B, 0x180F + 1))

    # Hangul fillers
    cps.add(0x115F)   # Hangul Choseong Filler
    cps.add(0x1160)   # Hangul Jungseong Filler
    cps.add(0x3164)   # Hangul Filler
    cps.add(0xFFA0)   # Halfwidth Hangul Filler

    # Khmer inherent vowels (visually empty in many contexts)
    cps.add(0x17B4)   # Khmer Vowel Inherent Aq
    cps.add(0x17B5)   # Khmer Vowel Inherent Aa

    # Soft hyphen (U+00AD) — invisible in most renderers
    cps.add(0x00AD)

    # Combining grapheme joiner (U+034F)
    cps.add(0x034F)

    # Arabic letter mark (U+061C)
    cps.add(0x061C)

    # Byte order mark / zero-width no-break space (U+FEFF)
    cps.add(0xFEFF)

    # Variation Selectors 1–15 (U+FE00–U+FE0E)
    # NOTE: U+FE0F (VS-16) is intentionally EXCLUDED — used for emoji presentation.
    cps.update(range(0xFE00, 0xFE0E + 1))  # 0xFE00..0xFE0E inclusive (15 chars)

    # Language tag (U+E0001)
    cps.add(0xE0001)

    # Tag characters (U+E0020–U+E007E) + Cancel tag (U+E007F)
    cps.update(range(0xE0020, 0xE007F + 1))

    # Variation Selectors Supplement (U+E0100–U+E01EF)
    cps.update(range(0xE0100, 0xE01EF + 1))

    return frozenset(cps)


INVISIBLE_CODEPOINTS: frozenset[int] = _build_invisible_codepoints()


# ---------------------------------------------------------------------------
# Compiled regex pattern
# ---------------------------------------------------------------------------

def _build_invisible_re() -> re.Pattern:
    """Build a compiled regex matching any invisible code point."""
    parts: list[str] = []
    # Sort for deterministic pattern construction
    for cp in sorted(INVISIBLE_CODEPOINTS):
        if cp > 0xFFFF:
            parts.append(f"\\U{cp:08X}")
        else:
            parts.append(f"\\u{cp:04X}")
    pattern = "[" + "".join(parts) + "]"
    return re.compile(pattern)


INVISIBLE_RE: re.Pattern = _build_invisible_re()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize_text(text: str) -> str:
    """Normalize text for security analysis.

    Applies:
      1. NFKC Unicode normalization
      2. NFD strip combining diacritical marks (Mn) EXCEPT U+FE0F
      3. NFC re-compose
      4. Strip invisible Unicode characters (INVISIBLE_CODEPOINTS)

    Args:
        text: Raw input string.

    Returns:
        Normalized string with invisible and combining characters removed.
    """
    normalized = unicodedata.normalize("NFKC", text)
    # Strip combining diacritical marks (Mn) to prevent keyword evasion
    # (e.g. "ig̀nore" bypassing "ignore"). Preserve U+FE0F for emoji.
    normalized = "".join(
        ch for ch in unicodedata.normalize("NFD", normalized)
        if unicodedata.category(ch) != "Mn" or ch == "️"
    )
    # Re-compose after stripping marks
    normalized = unicodedata.normalize("NFC", normalized)
    return INVISIBLE_RE.sub("", normalized)


def count_invisible_chars(text: str) -> int:
    """Count invisible Unicode characters in raw text (before normalization).

    Operates on the raw input without NFKC normalization so that the count
    reflects actual invisible characters as received.
    """
    return sum(1 for ch in text if ord(ch) in INVISIBLE_CODEPOINTS)
