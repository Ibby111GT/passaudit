#!/usr/bin/env python3
"""
PassAudit - Password Security Auditor
--------------------------------------
NIST SP 800-63B compliant password strength analyzer with entropy
calculation, crack time estimation, pattern detection, and hash cracking.

Usage:
    python pass_audit.py --password "MyP@ssw0rd"
    python pass_audit.py --file passwords.txt
    python pass_audit.py --demo
"""

import re
import sys
import math
import hashlib
import argparse
import string
from dataclasses import dataclass
from typing import Optional


COMMON_PASSWORDS = {
    "password", "123456", "password1", "12345678", "qwerty", "abc123",
    "monkey", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "passw0rd", "shadow", "123123", "superman",
    "qazwsx", "michael", "football", "password123", "admin", "welcome",
}

KEYBOARD_WALKS = [
    "qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx", "123456789",
]

LEET_MAP = str.maketrans("@$!0134", "aseiOIEA")

CRACK_SPEEDS = {
    "online_throttled":   100,
    "online_unthrottled": 10_000,
    "offline_md5":        10_000_000_000,
    "offline_bcrypt":     10_000,
}


@dataclass
class AuditResult:
    password: str
    length: int
    entropy_bits: float
    charset_size: int
    strength: str
    score: int
    crack_times: dict
    issues: list
    suggestions: list
    nist_compliant: bool


def calculate_entropy(password: str) -> tuple:
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in string.punctuation for c in password): charset += 32
    charset = max(charset, 1)
    entropy = len(password) * math.log2(charset)
    return round(entropy, 2), charset


def estimate_crack_times(entropy: float) -> dict:
    combinations = 2 ** entropy
    times = {}
    for scenario, speed in CRACK_SPEEDS.items():
        seconds = combinations / speed
        times[scenario] = _format_time(seconds)
    return times


def _format_time(seconds: float) -> str:
    if seconds < 1: return "instantly"
    if seconds < 60: return f"{seconds:.0f} seconds"
    if seconds < 3600: return f"{seconds/60:.0f} minutes"
    if seconds < 86400: return f"{seconds/3600:.0f} hours"
    if seconds < 31536000: return f"{seconds/86400:.0f} days"
    if seconds < 3.15e9: return f"{seconds/31536000:.0f} years"
    return "centuries+"


def detect_patterns(password: str) -> list:
    issues = []
    lower = password.lower()
    if lower in COMMON_PASSWORDS or lower.translate(LEET_MAP) in COMMON_PASSWORDS:
        issues.append("Common password or leet-speak variant detected")
    for walk in KEYBOARD_WALKS:
        if walk in lower or walk[::-1] in lower:
            issues.append(f"Keyboard walk pattern: '{walk}'")
            break
    if re.search(r"(.)\1{2,}", password):
        issues.append("Repeated character sequence detected")
    if re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde)", lower):
        issues.append("Sequential character pattern detected")
    if password.isdigit():
        issues.append("Password is all digits")
    elif password.isalpha():
        issues.append("Password is all letters")
    return issues


def check_nist_compliance(password: str, issues: list) -> tuple:
    nist_issues = []
    if len(password) < 8:
        nist_issues.append("Fails NIST minimum length of 8 characters")
    if any("Common password" in i for i in issues):
        nist_issues.append("Fails NIST: appears in known compromised password lists")
    return len(nist_issues) == 0, nist_issues


def score_password(length: int, entropy: float, issues: list) -> tuple:
    score = min(40, length * 3) + min(40, int(entropy / 3))
    score -= len(issues) * 8
    score = max(0, min(100, score))
    if score >= 80: strength = "VERY_STRONG"
    elif score >= 60: strength = "STRONG"
    elif score >= 40: strength = "FAIR"
    elif score >= 20: strength = "WEAK"
    else: strength = "VERY_WEAK"
    return score, strength


def build_suggestions(password: str, issues: list, entropy: float) -> list:
    suggestions = []
    if len(password) < 12:
        suggestions.append("Increase length to at least 12 characters")
    if not any(c.isupper() for c in password):
        suggestions.append("Add uppercase letters")
    if not any(c.islower() for c in password):
        suggestions.append("Add lowercase letters")
    if not any(c.isdigit() for c in password):
        suggestions.append("Add numbers")
    if not any(c in string.punctuation for c in password):
        suggestions.append("Add special characters (!@#$%^&*)")
    if issues:
        suggestions.append("Avoid predictable patterns and common words")
    if entropy < 40:
        suggestions.append("Consider using a passphrase (4+ random words)")
    return suggestions


def audit_password(password: str) -> AuditResult:
    entropy, charset = calculate_entropy(password)
    crack_times = estimate_crack_times(entropy)
    issues = detect_patterns(password)
    nist_ok, nist_issues = check_nist_compliance(password, issues)
    all_issues = issues + nist_issues
    score, strength = score_password(len(password), entropy, all_issues)
    suggestions = build_suggestions(password, all_issues, entropy)
    return AuditResult(
        password=password, length=len(password), entropy_bits=entropy,
        charset_size=charset, strength=strength, score=score,
        crack_times=crack_times, issues=all_issues,
        suggestions=suggestions, nist_compliant=nist_ok,
    )


def crack_hash(hash_value: str, wordlist_path: str):
    hash_len = len(hash_value)
    if hash_len == 32: algo = "md5"
    elif hash_len == 40: algo = "sha1"
    elif hash_len == 64: algo = "sha256"
    else:
        print(f"[!] Unrecognized hash length: {hash_len}")
        return None
    try:
        with open(wordlist_path, "r", errors="ignore") as f:
            for word in f:
                word = word.strip()
                h = hashlib.new(algo, word.encode()).hexdigest()
                if h == hash_value:
                    return word
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist_path}")
    return None


def print_result(result: AuditResult):
    icons = {"VERY_STRONG": "[+++]", "STRONG": "[++ ]", "FAIR": "[+  ]",
             "WEAK": "[-  ]", "VERY_WEAK": "[---]"}
    icon = icons.get(result.strength, "[ ? ]")
    masked = result.password[:2] + "*" * (result.length - 2)
    print(f"\n  Password  : {masked}")
    print(f"  Strength  : {icon} {result.strength}  (score: {result.score}/100)")
    print(f"  Length    : {result.length} chars")
    print(f"  Entropy   : {result.entropy_bits:.1f} bits (charset: {result.charset_size})")
    print(f"  NIST 800-63B: {'PASS' if result.nist_compliant else 'FAIL'}")
    print("  Crack Times:")
    for scenario, t in result.crack_times.items():
        print(f"    {scenario:<25} {t}")
    if result.issues:
        print("  Issues:")
        for i in result.issues: print(f"    - {i}")
    if result.suggestions:
        print("  Suggestions:")
        for s in result.suggestions: print(f"    * {s}")


def run_demo():
    demo_passwords = [
        "password", "P@ssw0rd!", "correct-horse-battery-staple",
        "Tr0ub4dor&3", "hunter2", "MyS3cur3P@$$w0rd2024!",
        "qwerty123", "aaaaaaaa",
    ]
    print("\n  PassAudit Demo - Sample Password Analysis")
    print("  " + "=" * 50)
    for pw in demo_passwords:
        result = audit_password(pw)
        icons = {"VERY_STRONG": "+++", "STRONG": "++ ", "FAIR": "+  ", "WEAK": "-  ", "VERY_WEAK": "---"}
        icon = icons.get(result.strength, "?")
        print(f"  [{icon}] {pw:<35} {result.strength:<12} {result.score}/100")
    print()


def main():
    parser = argparse.ArgumentParser(description="PassAudit - NIST SP 800-63B password auditor")
    parser.add_argument("--password", help="Single password to audit")
    parser.add_argument("--file", help="File with one password per line")
    parser.add_argument("--demo", action="store_true", help="Run demo with sample passwords")
    parser.add_argument("--hash", help="Hash value to crack")
    parser.add_argument("--wordlist", help="Wordlist for hash cracking")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.password:
        result = audit_password(args.password)
        print_result(result)
    elif args.file:
        try:
            with open(args.file) as f:
                passwords = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
        for pw in passwords:
            result = audit_password(pw)
            print_result(result)
    elif args.hash and args.wordlist:
        result = crack_hash(args.hash, args.wordlist)
        print(f"[+] Cracked: {result}" if result else "[-] Not found in wordlist")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
