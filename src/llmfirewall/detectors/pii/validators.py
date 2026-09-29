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
