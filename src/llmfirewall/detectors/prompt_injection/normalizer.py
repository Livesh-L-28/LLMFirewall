"""Text normalization utilities for adversarial prompt analysis."""

import re
import unicodedata
from typing import Tuple


def normalize_prompt_text(text: str) -> Tuple[str, str]:
    """Normalize input text to defeat basic evasion and obfuscation tactics.
    
    Performs:
    1. Unicode NFKC normalization (collapsing full-width characters, ligature folding).
    2. Zero-width character removal (e.g. U+200B zero-width space, U+FEFF BOM).
    3. Control character stripping (except standard whitespace / newlines).
    4. Consecutive whitespace collapse.
    
    Returns:
        Tuple[str, str]: (raw_cleaned_text, normalized_lowercase_text)
    """
    if not text:
        return "", ""

    # 1. Unicode NFKC normalization
    normalized = unicodedata.normalize("NFKC", text)

    # 2. Remove zero-width and invisible formatting characters
    # Zero-width spaces, joiners, non-joiners, soft hyphens, byte-order marks
    zero_width_pattern = re.compile(
        r"[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u2060\u180E]"
    )
    normalized = zero_width_pattern.sub("", normalized)

    # 3. Collapse whitespace and normalize newlines
    normalized_cleaned = re.sub(r"[ \t]+", " ", normalized)
    normalized_cleaned = re.sub(r"\r\n|\r", "\n", normalized_cleaned)

    # 4. Canonical lowercase representation
    normalized_lower = normalized_cleaned.lower()

    return normalized_cleaned, normalized_lower
