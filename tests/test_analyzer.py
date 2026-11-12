"""
Unit tests for the Password Analysis Engine.
Verifies entropy calculation, pattern recognition, blocklists, and strength scoring.
All test cases use synthetic non-credential testing strings.
"""
import pytest
from services.password_analyzer import (
    analyze_password,
    calculate_entropy,
    detect_repeated_characters,
    detect_sequential_characters,
    detect_keyboard_walks,
    detect_dictionary_words,
    check_common_passwords,
    format_duration
)


def test_empty_password():
    """Empty input should score 0 and classify as Very Weak."""
    res = analyze_password("")
    assert res["score"] == 0
    assert res["strength"] == "Very Weak"
    assert res["length"] == 0
    assert res["entropy_bits"] == 0.0
    assert "password" not in res


def test_none_password():
    """None input should be handled gracefully without crashing."""
    res = analyze_password(None)
    assert res["score"] == 0
    assert res["strength"] == "Very Weak"
    assert "password" not in res


def test_critically_short_password():
    """Short passwords (< 6 chars) must be capped as Very Weak."""
    res = analyze_password("a1!")
    assert res["score"] <= 18
    assert res["strength"] == "Very Weak"
    assert res["length"] == 3


def test_numeric_only_password():
    """Numeric-only credentials lack diversity and receive low score."""
    res = analyze_password("9482710385")
    assert res["has_number"] is True
    assert res["has_lowercase"] is False
    assert res["has_uppercase"] is False
    assert res["has_special"] is False
    assert res["score"] < 40
    assert "password" not in res


def test_lowercase_only_password():
    """Single-class lowercase credentials should be penalized."""
    res = analyze_password("abcdefghijk")
    assert res["has_lowercase"] is True
    assert res["has_uppercase"] is False
    assert res["score"] < 50


def test_common_password_exact_blocklist():
    """Known common passwords must be flagged and capped at Very Weak."""
    for pwd in ["password", "123456", "qwerty", "admin", "welcome"]:
        res = analyze_password(pwd)
        assert res["is_common_password"] is True
        assert res["score"] <= 15
        assert res["strength"] == "Very Weak"
        assert any("breached" in r.lower() or "common" in r.lower() for r in res["recommendations"])


def test_leet_speak_common_password():
    """Leet substitutions of common passwords should be caught."""
    res = analyze_password("p@ssw0rd")
    assert res["is_common_password"] is True
    assert res["score"] <= 18
    assert res["strength"] == "Very Weak"


def test_repeated_patterns():
    """Passwords with consecutive identical characters are penalized."""
    rep_info = detect_repeated_characters("aaaaabbbbb")
    assert rep_info["has_repeated_chars"] is True
    assert rep_info["max_consecutive_run"] == 5

    res = analyze_password("aaaaabbbbb")
    assert res["patterns"]["has_repeated_chars"] is True
    assert any("repetition" in reason.lower() or "repeated" in reason.lower() for reason in res["score_explanations"])


def test_sequential_patterns():
    """Sequential runs (alphabetical and numeric) are detected."""
    seq_info = detect_sequential_characters("abc987")
    assert seq_info["has_sequence"] is True
    assert len(seq_info["sequences"]) >= 2

    res = analyze_password("myabc123pass")
    assert res["patterns"]["has_sequence"] is True


def test_keyboard_walk_patterns():
    """Spatial keyboard walks (qwerty, asdf, etc.) are detected."""
    walk_info = detect_keyboard_walks("myqwertytest")
    assert walk_info["has_keyboard_walk"] is True
    assert any("qwerty" in w or "qwe" in w for w in walk_info["keyboard_walks"])


def test_dictionary_word_detection():
    """Dictionary stems (like 'banana', 'dragon') are detected."""
    res = analyze_password("banana99")
    assert res["patterns"]["has_dictionary_word"] is True
    assert "banana" in res["patterns"]["dictionary_words"]


def test_strong_random_password():
    """High-entropy random password should achieve Strong or Very Strong."""
    # Synthetic random test token
    synth_strong = "Kx9#m$L2!vP@9zQ&"
    res = analyze_password(synth_strong)
    assert res["length"] == 16
    assert res["has_uppercase"] is True
    assert res["has_lowercase"] is True
    assert res["has_number"] is True
    assert res["has_special"] is True
    assert res["entropy_bits"] >= 80
    assert res["score"] >= 80
    assert res["strength"] in ("Strong", "Very Strong")
    assert "password" not in res


def test_long_passphrase_nist():
    """Multi-word Diceware passphrase meets modern NIST recommendations."""
    passphrase = "correct-horse-battery-staple-2026!"
    res = analyze_password(passphrase)
    assert res["length"] >= 24
    assert res["score"] >= 80
    assert res["strength"] == "Very Strong"
    assert res["effective_entropy_bits"] >= 70


def test_zero_knowledge_guarantee():
    """CRITICAL SECURITY TEST: Ensure raw password is NEVER returned in response."""
    test_inputs = ["TestInputSecret123!", "UniqueTokenSecret_987$", "VerySecurePassphrase123#"]
    for inp in test_inputs:
        res = analyze_password(inp)
        assert "password" not in res
        assert inp not in str(res)


def test_format_duration_helper():
    """Verify human-readable crack time formatting."""
    assert format_duration(0.5) == "Instantly (< 1 second)"
    assert format_duration(30) == "30 seconds"
    assert format_duration(300) == "5 minutes"
    assert format_duration(7200) == "2 hours"
    assert format_duration(86400 * 5) == "5 days"
    assert format_duration(31536000 * 10) == "10 years"
    assert format_duration(3153600000 * 5) == "5 centuries"
