"""
core.py -- password strength evaluation logic.

NIST SP 800-63B informed checks: length, entropy estimation,
common password detection, and character-class coverage.
"""

import math
import re
import string
from dataclasses import dataclass, field
from typing import List

from .patterns import is_common, load_wordlist


@dataclass
class AuditResult:
    password:      str
    score:         int          = 0   # 0-100
    strength:      str          = 'WEAK'
    entropy_bits:  float        = 0.0
    issues:        List[str]    = field(default_factory=list)
    suggestions:   List[str]    = field(default_factory=list)


# Strength bands
_BANDS = [
    (80, 'VERY STRONG'),
    (60, 'STRONG'),
    (40, 'MODERATE'),
    (20, 'WEAK'),
    (0,  'VERY WEAK'),
]


def _charset_size(pw: str) -> int:
    size = 0
    if re.search(r'[a-z]', pw): size += 26
    if re.search(r'[A-Z]', pw): size += 26
    if re.search(r'[0-9]', pw): size += 10
    if re.search(r'[^a-zA-Z0-9]', pw): size += 32
    return max(size, 1)


def _entropy(pw: str) -> float:
    cs = _charset_size(pw)
    return len(pw) * math.log2(cs)


def _score_entropy(bits: float) -> int:
    # 128-bit target = full marks
    return min(int(bits / 128 * 50), 50)


def audit_password(password: str, wordlist: set = None) -> AuditResult:
    result = AuditResult(password=password)
    issues, suggestions = [], []
    bonus = 0

    # --- length check (NIST recommends >= 8, prefers >= 15) ---
    length = len(password)
    if length < 8:
        issues.append(f'Too short ({length} chars; minimum 8)')
    elif length < 12:
        suggestions.append('Consider using at least 12 characters')
    elif length >= 16:
        bonus += 10

    # --- character class diversity ---
    has_lower  = bool(re.search(r'[a-z]', password))
    has_upper  = bool(re.search(r'[A-Z]', password))
    has_digit  = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    classes = sum([has_lower, has_upper, has_digit, has_symbol])
    if classes < 2:
        issues.append('Uses only one character class')
        suggestions.append('Mix uppercase, lowercase, digits, and symbols')
    elif classes == 4:
        bonus += 10

    # --- common password check ---
    wl = wordlist if wordlist is not None else load_wordlist()
    if is_common(password, wl):
        issues.append('Password found in common password list')
        suggestions.append('Choose a unique passphrase instead')

    # --- repeated characters ---
    if re.search(r'(.)\1{2,}', password):
        issues.append('Contains 3+ repeated characters in a row')
        bonus -= 5

    # --- sequential patterns ---
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|qwe|asd|zxc)',
                 password.lower()):
        issues.append('Contains common sequential pattern')
        bonus -= 5

    # --- entropy ---
    bits = _entropy(password)
    result.entropy_bits = round(bits, 1)
    score = _score_entropy(bits) + (classes * 5) + bonus
    score = max(0, min(score, 100))

    # apply penalty for issues
    score = max(0, score - len(issues) * 10)

    result.score = score
    result.strength = next(label for threshold, label in _BANDS if score >= threshold)
    result.issues = issues
    result.suggestions = suggestions
    return result
