"""Validation utilities for PII patterns (Luhn algorithm, IP validation)."""

import ipaddress
import re


def luhn_checksum_is_valid(card_number: str) -> bool:
    """Verify numeric string passes the Luhn checksum (MOD 10 algorithm).
    
    Used by payment processors to validate credit card numbers and avoid false positives
    on random 13-19 digit numbers.
    """
    digits_only = re.sub(r"[^\d]", "", card_number)
    if not (13 <= len(digits_only) <= 19):
        return False

    total = 0
    # Process from right to left; double every second digit starting from the second-to-last
    reverse_digits = [int(d) for d in reversed(digits_only)]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += digit

    return total % 10 == 0


def is_valid_ip_address(ip_str: str) -> bool:
    """Validate that string represents a syntactically valid IPv4 or IPv6 address.
    
    Prevents false positives on version numbers (e.g. 1.2.3.4 where octets exceed 255)
    or invalid numeric groups.
    """
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def is_valid_ssn(candidate: str, full_text: str = "", start_pos: int = 0) -> bool:
    """Validate standard US Social Security Number (SSN) structure and context.

    Validates SSA structural rules:
      - Area (first 3 digits): 001-899, excluding 000, 666, and 900-999.
      - Group (middle 2 digits): 01-99, excluding 00.
      - Serial (last 4 digits): 0001-9999, excluding 0000.

    Context safety:
      - Avoids false positives on order reference codes, part numbers, and tracking IDs
        (e.g., 'Order reference code 123-45-6789') unless explicit SSN/identity context is present.
    """
    parts = candidate.split("-")
    if len(parts) != 3:
        return False

    area, group, serial = parts[0], parts[1], parts[2]
    if len(area) != 3 or len(group) != 2 or len(serial) != 4:
        return False

    try:
        a_int, g_int, s_int = int(area), int(group), int(serial)
    except ValueError:
        return False

    # SSA structural invariants
    if a_int == 0 or a_int == 666 or a_int >= 900:
        return False
    if g_int == 0 or s_int == 0:
        return False

    # Context inspection: suppress false positives on non-PII reference numbers
    if full_text and start_pos >= 0:
        prefix_window = full_text[max(0, start_pos - 35):start_pos].lower()
        non_pii_indicators = (
            "order",
            "tracking",
            "invoice",
            "part",
            "sku",
            "product",
            "item",
            "ref code",
            "reference code",
        )
        if any(ind in prefix_window for ind in non_pii_indicators):
            ssn_affirmations = ("ssn", "social", "taxpayer", "tin", "identity", "id:")
            if not any(aff in prefix_window for aff in ssn_affirmations):
                return False

    return True
