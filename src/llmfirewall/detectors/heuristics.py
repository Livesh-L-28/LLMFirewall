"""Deterministic input normalization, token heuristics, and pre-filtering."""

import unicodedata
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field


class TokenHeuristics(BaseModel):
    """Lightweight, deterministic structural signals computed from input text."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    char_count: int = Field(default=0, ge=0)
    token_count_approx: int = Field(default=0, ge=0)
    non_ascii_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    control_char_count: int = Field(default=0, ge=0)
    delimiter_density: float = Field(default=0.0, ge=0.0)
    has_role_markers: bool = Field(default=False)
    has_instruction_markers: bool = Field(default=False)
    has_code_blocks: bool = Field(default=False)
    has_hex_or_base64_tokens: bool = Field(default=False)
    suspicious_token_count: int = Field(default=0, ge=0)


# Deterministic Cyrillic homoglyph confusable translation table
CYRILLIC_HOMOGLYPH_TABLE = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0420": "P", "\u0421": "C",
    "\u0422": "T", "\u0425": "X", "\u0406": "I", "\u0408": "J", "\u0405": "S",
    "\u0432": "b", "\u043c": "m", "\u043d": "h", "\u0442": "t",
})


def normalize_detection_input(text: str) -> Tuple[str, str]:
    """Normalize input text deterministically using NFKC, homoglyph folding, and lowercase canonicalization.
    
    Returns:
        (canonical_text, lower_text)
    """
    if not text:
        return "", ""
    # Standard NFKC normalization handles compatible Unicode equivalents
    nfkc = unicodedata.normalize("NFKC", text)
    # Fold Cyrillic homoglyphs commonly used in evasion attacks
    folded = nfkc.translate(CYRILLIC_HOMOGLYPH_TABLE)
    # Strip null bytes, non-printable control characters, and zero-width/format markers (Cc, Cf)
    cleaned_chars = [
        ch for ch in folded
        if ch in ("\n", "\r", "\t") or (ch >= " " and unicodedata.category(ch) not in ("Cc", "Cf"))
    ]
    canonical = "".join(cleaned_chars)
    return canonical, canonical.lower()



def compute_token_heuristics(text: str) -> TokenHeuristics:
    """Analyze deterministic token signals without invoking heavy model parsers."""
    if not text:
        return TokenHeuristics()

    char_len = len(text)
    words = text.split()
    word_count = len(words)

    # Unicode non-ascii analysis
    non_ascii = sum(1 for ch in text if ord(ch) > 127)
    non_ascii_ratio = non_ascii / char_len if char_len > 0 else 0.0

    # Control chars (ignoring standard whitespace)
    ctrl_count = sum(1 for ch in text if ord(ch) < 32 and ch not in ("\n", "\r", "\t"))

    # Delimiters and special framing tokens: <, >, {, }, [, ], |, `, \, #, @
    delimiters = sum(1 for ch in text if ch in "<>{}[|]`\\#@")
    delim_density = (delimiters / word_count) if word_count > 0 else 0.0

    lower = text.lower()

    # Structural prompt markers (heuristics only, NOT automatic classification)
    role_markers = any(
        m in lower for m in (
            "system:", "user:", "assistant:", "<|im_start|>", "<|system|>",
            "[inst]", "[/inst]", "<<sys>>", "<|endoftext|>"
        )
    )
    instruction_markers = any(
        m in lower for m in (
            "ignore previous", "disregard all", "override instructions",
            "jailbreak", "do anything now", "developer mode", "system prompt"
        )
    )
    has_code_blocks = "```" in text or "<code>" in lower

    # High-entropy or encoded token patterns (e.g., base64 or hex blocks >= 32 chars)
    has_encoded = False
    for word in words:
        clean_word = word.strip("=;:'\",.()[]{}")
        if len(clean_word) >= 32 and (
            all(c in "0123456789abcdefABCDEF" for c in clean_word)
            or all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" for c in clean_word)
        ):
            has_encoded = True
            break

    suspicious_score = (
        (2 if role_markers else 0)
        + (2 if instruction_markers else 0)
        + (1 if ctrl_count > 0 else 0)
        + (1 if delim_density > 0.5 else 0)
        + (1 if has_encoded else 0)
    )

    return TokenHeuristics(
        char_count=char_len,
        token_count_approx=word_count,
        non_ascii_ratio=round(non_ascii_ratio, 4),
        control_char_count=ctrl_count,
        delimiter_density=round(delim_density, 4),
        has_role_markers=role_markers,
        has_instruction_markers=instruction_markers,
        has_code_blocks=has_code_blocks,
        has_hex_or_base64_tokens=has_encoded,
        suspicious_token_count=suspicious_score,
    )
