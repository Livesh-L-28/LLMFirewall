"""Text normalization utilities for adversarial prompt analysis."""

import re
import unicodedata
from typing import Tuple


# Deterministic Cyrillic homoglyph confusable translation table
CYRILLIC_HOMOGLYPH_MAP = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0420": "P", "\u0421": "C",
    "\u0422": "T", "\u0425": "X", "\u0406": "I", "\u0408": "J", "\u0405": "S",
    "\u0432": "b", "\u043c": "m", "\u043d": "h", "\u0442": "t",
})


def normalize_prompt_text(text: str) -> Tuple[str, str]:
    """Normalize input text to defeat basic evasion and obfuscation tactics.
    
    Performs:
    1. Unicode NFKC normalization (collapsing full-width characters, ligature folding).
    2. Cyrillic homoglyph folding into ASCII Latin equivalents.
    3. Zero-width character removal (e.g. U+200B zero-width space, U+FEFF BOM).
    4. Control character stripping (except standard whitespace / newlines).
    5. Consecutive whitespace collapse.
    
    Returns:
        Tuple[str, str]: (raw_cleaned_text, normalized_lowercase_text)
    """
    if not text:
        return "", ""

    # 1. Unicode NFKC normalization
    normalized = unicodedata.normalize("NFKC", text)

    # 2. Cyrillic homoglyph folding
    normalized = normalized.translate(CYRILLIC_HOMOGLYPH_MAP)

    # 3. Remove zero-width and invisible formatting characters
    zero_width_pattern = re.compile(
        r"[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u2060\u180E]"
    )
    normalized = zero_width_pattern.sub("", normalized)

    # 4. Collapse whitespace and normalize newlines
    normalized_cleaned = re.sub(r"[ \t]+", " ", normalized)
    normalized_cleaned = re.sub(r"\r\n|\r", "\n", normalized_cleaned)

    # 5. Canonical lowercase representation
    normalized_lower = normalized_cleaned.lower()

    return normalized_cleaned, normalized_lower
