"""
patterns.py -- common password list and wordlist utilities.
"""

import os
from typing import Set


# Top common passwords for offline checks
_BUILTIN_COMMON = {
    '123456', 'password', '12345678', 'qwerty', '123456789',
    '12345', '1234', '111111', '1234567', 'dragon',
    '123123', 'baseball', 'abc123', 'football', 'monkey',
    'letmein', 'shadow', 'master', '666666', 'qwertyuiop',
    '123321', 'mustang', '1234567890', 'michael', '654321',
    'superman', '1qaz2wsx', '7777777', '121212', '000000',
    'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan',
    'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster',
    'soccer', 'harley', 'batman', 'andrew', 'tigger',
    'sunshine', 'iloveyou', 'charlie', 'robert', 'thomas',
    'hockey', 'ranger', 'daniel', 'starwars', 'klaster',
    'george', 'computer', 'michelle', 'jessica', 'pepper',
    '1111', 'zxcvbn', '555555', '11111111', '131313',
    'freedom', '777777', 'pass', 'maggie', '159753',
    'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese',
    'amanda', 'summer', 'love', 'ashley', 'nicole',
    'chelsea', 'biteme', 'matthew', 'access', 'yankees',
    '987654321', 'dallas', 'austin', 'thunder', 'taylor',
    'matrix', 'minecraft', 'pokemon', 'welcome', 'hello',
    'login', 'admin', 'test', 'root', 'pass123',
    'password1', 'abc',
}

_cached_wordlist: Set[str] = None


def load_wordlist(path: str = None) -> Set[str]:
    """Return wordlist set. Loads from file if path given, else built-in."""
    global _cached_wordlist
    if path is None:
        return _BUILTIN_COMMON
    if _cached_wordlist is None:
        if not os.path.isfile(path):
            raise FileNotFoundError(f'Wordlist not found: {path}')
        with open(path, 'r', errors='ignore') as fh:
            _cached_wordlist = {line.strip().lower() for line in fh if line.strip()}
    return _cached_wordlist


def is_common(password: str, wordlist: Set[str] = None) -> bool:
    """Return True if password appears in wordlist (case-insensitive)."""
    wl = wordlist if wordlist is not None else _BUILTIN_COMMON
    return password.lower() in wl
