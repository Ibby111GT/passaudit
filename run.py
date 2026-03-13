#!/usr/bin/env python3
"""
run.py -- PassAudit CLI entry point.

Audits passwords from the command line or a file.

Usage:
    python run.py 'MyP@ssw0rd!'
    python run.py --file passwords.txt
    python run.py --file passwords.txt --wordlist rockyou.txt --json
"""

import argparse
import json
import sys

from passaudit.core     import audit_password
from passaudit.patterns import load_wordlist


_COLOUR = {
    'VERY STRONG': '\033[32m',
    'STRONG':      '\033[32m',
    'MODERATE':    '\033[33m',
    'WEAK':        '\033[31m',
    'VERY WEAK':   '\033[31m',
}
_RESET = '\033[0m'


def _colourise(strength: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{_COLOUR.get(strength, '')}{text}{_RESET}"


def print_result(result, use_json: bool = False) -> None:
    if use_json:
        print(json.dumps({
            'password': result.password,
            'score':    result.score,
            'strength': result.strength,
            'entropy':  result.entropy_bits,
            'issues':   result.issues,
            'suggestions': result.suggestions,
        }, indent=2))
        return

    pw_display = result.password if len(result.password) <= 20 else result.password[:17] + '...'
    print(f"  Password : {pw_display}")
    print(f"  Score    : {result.score}/100")
    print(f"  Strength : {_colourise(result.strength, result.strength)}")
    print(f"  Entropy  : {result.entropy_bits} bits")
    if result.issues:
        print(f"  Issues   :")
        for issue in result.issues:
            print(f"    - {issue}")
    if result.suggestions:
        print(f"  Tips     :")
        for tip in result.suggestions:
            print(f"    -> {tip}")
    print()


def main() -> None:
    p = argparse.ArgumentParser(description='PassAudit -- NIST-informed password auditor')
    p.add_argument('password', nargs='?', help='Password to audit')
    p.add_argument('--file', '-f', metavar='FILE',
                   help='File containing one password per line')
    p.add_argument('--wordlist', '-w', metavar='FILE',
                   help='Custom wordlist file (e.g. rockyou.txt)')
    p.add_argument('--json', action='store_true', help='Output as JSON')
    args = p.parse_args()

    wordlist = load_wordlist(args.wordlist) if args.wordlist else None

    passwords = []
    if args.password:
        passwords.append(args.password)
    elif args.file:
        try:
            with open(args.file) as fh:
                passwords = [line.strip() for line in fh if line.strip()]
        except FileNotFoundError:
            print(f'[!] File not found: {args.file}', file=sys.stderr)
            sys.exit(1)
    else:
        p.print_help()
        sys.exit(0)

    for pw in passwords:
        result = audit_password(pw, wordlist=wordlist)
        print_result(result, use_json=args.json)


if __name__ == '__main__':
    main()
