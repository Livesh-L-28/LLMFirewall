"""Entropy calculation utilities for high-randomness secret analysis."""

import math
from collections import Counter


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string (bits per symbol).
    
    Higher entropy indicates greater randomness, characteristic of generated secrets,
    cryptographic keys, and tokens, contrasting with natural language text or English words.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy
