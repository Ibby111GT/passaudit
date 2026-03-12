# PassAudit — Password Security Auditor

A NIST SP 800-63B compliant password auditor with entropy analysis, crack time estimation,
pattern detection, and dictionary hash cracking. Built with Python's standard library — no external dependencies.

## Features

- NIST SP 800-63B policy compliance checking
- Shannon entropy calculation (bits) and effective charset size
- Crack time estimation across 4 attack scenarios
- Pattern detection: keyboard walks, leet speak, repetition, sequences
- Common password / breach list checking
- MD5 / SHA-1 / SHA-256 dictionary hash cracking
- Batch audit mode for credential lists
- Score 0-100 with VERY_WEAK → VERY_STRONG rating
- Demo mode with 8 sample passwords

## Usage

```bash
# Audit a single password
python pass_audit.py --password "MyP@ssw0rd123"

# Demo mode (no input needed)
python pass_audit.py --demo

# Batch audit a password list
python pass_audit.py --file passwords.txt

# Crack a hash against a wordlist
python pass_audit.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
```

## Crack Time Scenarios

| Scenario | Speed |
|----------|-------|
| Online (throttled) | 100 attempts/sec |
| Online (unthrottled) | 10,000 attempts/sec |
| Offline MD5 | 10 billion/sec |
| Offline bcrypt | 10,000/sec |

## NIST SP 800-63B Compliance

- Minimum 8 character length requirement
- Checks against known compromised password lists
- No arbitrary composition rules enforced
- Entropy-based strength rather than complexity rules

## Requirements

- Python 3.10+
- No external dependencies (pure stdlib)

## Ethical Use

For authorized security audits and internal credential hygiene reviews only.
Never audit passwords or crack hashes without explicit written authorization.
