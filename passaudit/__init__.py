"""
passaudit -- password auditing toolkit.

Exposed API:
    from passaudit import audit_password, audit_file
"""

from .core     import audit_password
from .patterns import load_wordlist

__version__ = '0.2.0'
__all__     = ['audit_password', 'load_wordlist']
