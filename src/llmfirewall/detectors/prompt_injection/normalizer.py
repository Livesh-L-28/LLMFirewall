"""Text normalization utilities for adversarial prompt analysis."""

import base64
from dataclasses import dataclass, field
import hashlib
import html
import re
import string
import unicodedata
from urllib.parse import unquote
from typing import Any, Dict, List, Optional, Set, Tuple


# Deterministic Cyrillic homoglyph confusable translation table
CYRILLIC_HOMOGLYPH_MAP = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0420": "P", "\u0421": "C",
    "\u0422": "T", "\u0425": "X", "\u0406": "I", "\u0408": "J", "\u0405": "S",
    "\u0432": "b", "\u043c": "m", "\u043d": "h", "\u0442": "t",
})

# Leetspeak digit and symbol substitution translation table
LEETSPEAK_MAP = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i",
})

PRINTABLE_CHARS = set(string.printable)


@dataclass
class NormalizerConfig:
    """Configuration governing bounded multi-stage deterministic normalization."""
    max_input_length: int = 100_000
    max_decoding_depth: int = 2
    max_decoded_size: int = 65_536  # 64 KB total inspection buffer ceiling
    min_base64_length: int = 16
    min_hex_length: int = 16
    min_printable_ratio: float = 0.85
    enable_base64_decoding: bool = True
    enable_hex_decoding: bool = True
    enable_url_decoding: bool = True
    enable_leetspeak_normalization: bool = True
    enable_bracket_normalization: bool = True
    enable_html_unescaping: bool = True
    decode_isolated_base64: bool = False


class NormalizationArtifact(tuple):
    """Subclass of tuple (raw_cleaned_text, normalized_lower) preserving 100% backward compatibility."""
    raw_cleaned_text: str
    normalized_lower: str
    original_text: str
    inspection_buffers: List[str]
    transformations: List[Dict[str, Any]]

    def __new__(
        cls,
        raw_cleaned_text: str,
        normalized_lower: str,
        original_text: str = "",
        inspection_buffers: Optional[List[str]] = None,
        transformations: Optional[List[Dict[str, Any]]] = None,
    ):
        instance = super().__new__(cls, (raw_cleaned_text, normalized_lower))
        instance.raw_cleaned_text = raw_cleaned_text
        instance.normalized_lower = normalized_lower
        instance.original_text = original_text
        instance.inspection_buffers = list(inspection_buffers or [])
        instance.transformations = list(transformations or [])
        return instance


class MultiStageNormalizer:
    """Bounded, deterministic normalization pipeline for detecting obfuscated inputs."""

    def __init__(self, config: Optional[NormalizerConfig] = None) -> None:
        self.config = config or NormalizerConfig()

    def normalize(self, text: str) -> NormalizationArtifact:
        """Execute bounded multi-stage normalization pipeline.

        Returns:
            NormalizationArtifact: Tuple (raw_cleaned, norm_lower) with inspection_buffers.
        """
        if not text:
            return NormalizationArtifact("", "", original_text="")

        original_text = text
        # Enforce max input length limit
        if len(text) > self.config.max_input_length:
            text = text[: self.config.max_input_length]

        # 1. Base Canonical Normalization (Unicode NFKC, homoglyphs, zero-width chars, whitespace)
        raw_cleaned, norm_lower = self._canonical_normalize(text)

        inspection_buffers: List[str] = []
        transformations: List[Dict[str, Any]] = []
        seen_hashes: Set[str] = {self._hash_text(norm_lower), self._hash_text(raw_cleaned)}
        total_decoded_bytes = 0

        # Initial queue for recursive decoding stages
        current_queue: List[Tuple[str, int]] = [(raw_cleaned, 1)]

        while current_queue:
            current_text, depth = current_queue.pop(0)
            if depth > self.config.max_decoding_depth:
                continue

            discovered_this_pass: List[str] = []

            # Stage A: URL percent-decoding
            if self.config.enable_url_decoding and "%" in current_text:
                url_decoded = self._decode_url_percent(current_text)
                if url_decoded and url_decoded != current_text:
                    h = self._hash_text(url_decoded)
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        discovered_this_pass.append(url_decoded)
                        transformations.append({
                            "type": "url_percent_decode",
                            "depth": depth,
                            "length": len(url_decoded),
                        })

            # Stage B: HTML entity unescaping
            if self.config.enable_html_unescaping and "&" in current_text:
                html_decoded = self._unescape_html_entities(current_text)
                if html_decoded and html_decoded != current_text:
                    h = self._hash_text(html_decoded)
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        discovered_this_pass.append(html_decoded)
                        transformations.append({
                            "type": "html_entity_unescape",
                            "depth": depth,
                            "length": len(html_decoded),
                        })

            # Stage C: Bracket-separated and spaced character folding
            if self.config.enable_bracket_normalization:
                bracket_norm = self._normalize_bracket_separated(current_text)
                if bracket_norm and bracket_norm != current_text:
                    h = self._hash_text(bracket_norm)
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        discovered_this_pass.append(bracket_norm)
                        transformations.append({
                            "type": "bracket_separated_collapse",
                            "depth": depth,
                            "length": len(bracket_norm),
                        })

            # Stage D: Leetspeak shadow normalization
            if self.config.enable_leetspeak_normalization:
                leet_norm = self._normalize_leetspeak(current_text)
                if leet_norm and leet_norm != current_text:
                    h = self._hash_text(leet_norm)
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        discovered_this_pass.append(leet_norm)
                        transformations.append({
                            "type": "leetspeak_normalization",
                            "depth": depth,
                            "length": len(leet_norm),
                        })

            # Stage E: Safe Base64 candidate detection and decoding
            if self.config.enable_base64_decoding:
                b64_decoded_list = self._detect_and_decode_base64(current_text)
                for candidate_token, decoded_content in b64_decoded_list:
                    h = self._hash_text(decoded_content)
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        discovered_this_pass.append(decoded_content)
                        transformations.append({
                            "type": "base64_decode",
                            "depth": depth,
                            "candidate_preview": candidate_token[:32],
                            "decoded_preview": decoded_content[:64],
                            "length": len(decoded_content),
                        })

            # Stage F: Hexadecimal candidate detection and decoding
            if self.config.enable_hex_decoding:
                hex_decoded_list = self._detect_and_decode_hex(current_text)
                for candidate_token, decoded_content in hex_decoded_list:
                    h = self._hash_text(decoded_content)
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        discovered_this_pass.append(decoded_content)
                        transformations.append({
                            "type": "hex_decode",
                            "depth": depth,
                            "candidate_preview": candidate_token[:32],
                            "decoded_preview": decoded_content[:64],
                            "length": len(decoded_content),
                        })

            # Process discovered candidates with memory bounds
            for item in discovered_this_pass:
                item_size = len(item.encode("utf-8", errors="replace"))
                if total_decoded_bytes + item_size > self.config.max_decoded_size:
                    # Enforce hard ceiling on total decoded memory size
                    break
                total_decoded_bytes += item_size
                inspection_buffers.append(item)

                # Queue for next recursion level if depth allows
                if depth + 1 <= self.config.max_decoding_depth:
                    current_queue.append((item, depth + 1))

        return NormalizationArtifact(
            raw_cleaned_text=raw_cleaned,
            normalized_lower=norm_lower,
            original_text=original_text,
            inspection_buffers=inspection_buffers,
            transformations=transformations,
        )

    def _canonical_normalize(self, text: str) -> Tuple[str, str]:
        """Performs standard Unicode NFKC, homoglyph replacement, and whitespace normalization."""
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

    def _decode_url_percent(self, text: str) -> Optional[str]:
        """Decode URL percent-encoded characters if valid sequences are present."""
        if not re.search(r"%[0-9a-fA-F]{2}", text):
            return None
        try:
            unquoted = unquote(text)
            return unquoted if unquoted != text else None
        except Exception:
            return None

    def _unescape_html_entities(self, text: str) -> Optional[str]:
        """Unescape HTML named and numeric character entities."""
        if not re.search(r"&(?:[a-zA-Z0-9]+|#\d+|#[xX][0-9a-fA-F]+);", text):
            return None
        try:
            unescaped = html.unescape(text)
            return unescaped if unescaped != text else None
        except Exception:
            return None

    def _normalize_bracket_separated(self, text: str) -> Optional[str]:
        """Collapse sequences of bracketed or spaced characters into words."""
        # Pattern for sequences like [V][O][I][D] or [A][L][L] or (V)(O)(I)(D)
        bracket_seq_pattern = re.compile(r"(?:\[([A-Za-z0-9])\]|\(([A-Za-z0-9])\)|<([A-Za-z0-9])>){3,}")
        
        has_change = False
        def _collapse_brackets(match: re.Match) -> str:
            nonlocal has_change
            full = match.group(0)
            chars = re.findall(r"\[([A-Za-z0-9])\]|\(([A-Za-z0-9])\)|<([A-Za-z0-9])>", full)
            collapsed = "".join(c[0] or c[1] or c[2] for c in chars)
            if len(collapsed) >= 3:
                has_change = True
                return collapsed
            return full

        collapsed_text = bracket_seq_pattern.sub(_collapse_brackets, text)

        # Spaced single letters in sequences >= 4 (e.g. "v o i d  a l l  r u l e s")
        spaced_pattern = re.compile(r"\b([A-Za-z])(?:\s+([A-Za-z])){3,}\b")
        def _collapse_spaces(match: re.Match) -> str:
            nonlocal has_change
            full = match.group(0)
            collapsed = re.sub(r"\s+", "", full)
            if len(collapsed) >= 4:
                has_change = True
                return collapsed
            return full

        collapsed_text = spaced_pattern.sub(_collapse_spaces, collapsed_text)

        return collapsed_text if has_change else None

    def _normalize_leetspeak(self, text: str) -> Optional[str]:
        """Transliterate numeric and symbolic leetspeak characters in candidate words."""
        # Do not leet-translate isolated base64 payloads
        stripped = text.strip()
        if (stripped.endswith("=") or len(stripped) >= 20) and re.match(r"^[A-Za-z0-9+/=]+$", stripped):
            return None

        # Target tokens (length >= 3) that contain a mixture of letters and leetspeak numbers
        candidate_word_pattern = re.compile(r"\b(?=[a-zA-Z0-9@$!]*[a-zA-Z])(?=[a-zA-Z0-9@$!]*[0-9@$!])[a-zA-Z0-9@$!]{2,}\b")
        
        has_change = False
        def _leet_sub(match: re.Match) -> str:
            nonlocal has_change
            word = match.group(0)
            translated = word.translate(LEETSPEAK_MAP)
            if translated != word:
                has_change = True
                return translated
            return word

        shadow_text = candidate_word_pattern.sub(_leet_sub, text)
        return shadow_text if has_change else None

    def _detect_and_decode_base64(self, text: str) -> List[Tuple[str, str]]:
        """Identify candidate Base64 strings and safely decode printable UTF-8 content."""
        # Matches base64 candidate strings of length >= 16
        b64_pattern = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?|[A-Za-z0-9+/=]{16,}")
        candidates = b64_pattern.findall(text)
        results: List[Tuple[str, str]] = []

        for candidate in candidates:
            cand_clean = candidate.strip()
            if len(cand_clean) < self.config.min_base64_length:
                continue

            # Conservative recognition: isolated standalone candidate requires explicit directive or config
            is_isolated = (cand_clean == text.strip())
            has_directive = bool(re.search(r"\b(?:decode|base64|b64|execute|run|eval|payload)\b", text, re.IGNORECASE))
            if is_isolated and not has_directive and not self.config.decode_isolated_base64:
                continue

            # Ensure valid 4-byte padding
            padded = cand_clean
            missing_padding = len(padded) % 4
            if missing_padding != 0:
                padded += "=" * (4 - missing_padding)

            try:
                decoded_bytes = base64.b64decode(padded, validate=True)
            except Exception:
                try:
                    decoded_bytes = base64.urlsafe_b64decode(padded)
                except Exception:
                    continue

            if len(decoded_bytes) < 8 or len(decoded_bytes) > self.config.max_decoded_size:
                continue

            try:
                decoded_str = decoded_bytes.decode("utf-8")
            except UnicodeDecodeError:
                continue

            # Check printable character ratio to discard binary/encrypted data
            printable_count = sum(1 for ch in decoded_str if ch in PRINTABLE_CHARS)
            ratio = printable_count / len(decoded_str)
            if ratio >= self.config.min_printable_ratio and len(set(decoded_str)) > 3:
                results.append((cand_clean, decoded_str))

        return results

    def _detect_and_decode_hex(self, text: str) -> List[Tuple[str, str]]:
        """Identify candidate Hex strings and safely decode printable UTF-8 content."""
        hex_pattern = re.compile(r"\b(?:0x)?([0-9a-fA-F]{16,})\b")
        candidates = hex_pattern.findall(text)
        results: List[Tuple[str, str]] = []

        for candidate in candidates:
            if len(candidate) % 2 != 0 or len(candidate) < self.config.min_hex_length:
                continue

            # Conservative recognition: isolated standalone candidate requires explicit directive or config
            is_isolated = (candidate == text.strip() or f"0x{candidate}" == text.strip())
            has_directive = bool(re.search(r"\b(?:decode|hex|execute|run|eval|payload)\b", text, re.IGNORECASE))
            if is_isolated and not has_directive and not self.config.decode_isolated_base64:
                continue

            try:
                decoded_bytes = bytes.fromhex(candidate)
            except ValueError:
                continue

            if len(decoded_bytes) < 8 or len(decoded_bytes) > self.config.max_decoded_size:
                continue

            try:
                decoded_str = decoded_bytes.decode("utf-8")
            except UnicodeDecodeError:
                continue

            printable_count = sum(1 for ch in decoded_str if ch in PRINTABLE_CHARS)
            ratio = printable_count / len(decoded_str)
            if ratio >= self.config.min_printable_ratio and len(set(decoded_str)) > 3:
                results.append((candidate, decoded_str))

        return results

    def _hash_text(self, text: str) -> str:
        """Fast SHA-256 hash of text for cycle prevention."""
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# Global default multi-stage normalizer instance
_default_normalizer = MultiStageNormalizer()


def normalize_prompt_text(
    text: str,
    config: Optional[NormalizerConfig] = None,
) -> NormalizationArtifact:
    """Normalize input text to defeat basic evasion and obfuscation tactics.

    Preserves 100% backward compatibility by returning a NormalizationArtifact (a tuple of
    raw_cleaned_text and normalized_lowercase_text), while also populating decoded
    inspection buffers and transformation metadata.

    Args:
        text: Input prompt text string.
        config: Optional custom NormalizerConfig tuning decoding bounds.

    Returns:
        NormalizationArtifact: Subclass of Tuple[str, str] with inspection_buffers.
    """
    if config is not None:
        return MultiStageNormalizer(config).normalize(text)
    return _default_normalizer.normalize(text)
