"""
Unit tests for the Cryptographically Secure Password Generator.
Verifies entropy, character set constraints, shuffle randomness, and boundary validation.
"""
import pytest
import string
from services.password_generator import (
    generate_secure_password,
    generate_passphrase,
    AMBIGUOUS_CHARS,
    SAFE_SYMBOLS
)


def test_generator_default():
    """Default generator invocation produces 16 characters with all sets."""
    res = generate_secure_password()
    pwd = res["password"]
    assert len(pwd) == 16
    assert res["length"] == 16
    assert any(c.islower() for c in pwd)
    assert any(c.isupper() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(c in SAFE_SYMBOLS for c in pwd)


def test_generator_custom_length():
    """Generator respects requested lengths."""
    for l in [8, 12, 24, 64, 128]:
        res = generate_secure_password(length=l)
        assert len(res["password"]) == l


def test_generator_category_selection():
    """Category toggles restrict character sets correctly."""
    # Digits only
    res_digits = generate_secure_password(
        length=10,
        use_upper=False,
        use_lower=False,
        use_digits=True,
        use_special=False
    )
    assert res_digits["password"].isdigit()

    # Uppercase only
    res_upper = generate_secure_password(
        length=12,
        use_upper=True,
        use_lower=False,
        use_digits=False,
        use_special=False
    )
    assert res_upper["password"].isupper()
    assert res_upper["password"].isalpha()


def test_avoid_ambiguous_characters():
    """When avoid_ambiguous is True, confusing characters must be omitted."""
    # Generate 50 passwords to verify statistical absence of ambiguous chars
    for _ in range(50):
        res = generate_secure_password(
            length=32,
            use_upper=True,
            use_lower=True,
            use_digits=True,
            use_special=True,
            avoid_ambiguous=True
        )
        pwd = res["password"]
        for amb in AMBIGUOUS_CHARS:
            assert amb not in pwd, f"Ambiguous character '{amb}' was found in generated password."


def test_invalid_generator_parameters():
    """Invalid arguments raise ValueError."""
    # Length too short (< 6)
    with pytest.raises(ValueError, match="at least 6"):
        generate_secure_password(length=5)

    # Length too long (> 128)
    with pytest.raises(ValueError, match="cannot exceed 128"):
        generate_secure_password(length=150)

    # No category selected
    with pytest.raises(ValueError, match="At least one character category"):
        generate_secure_password(
            use_upper=False,
            use_lower=False,
            use_digits=False,
            use_special=False
        )


def test_diceware_passphrase_generator():
    """Passphrase mode generates multi-word phrase with valid word counts."""
    res = generate_passphrase(word_count=4, separator="-")
    words = res["passphrase"].split("-")
    assert len(words) == 4
    assert res["word_count"] == 4
    assert res["entropy_bits"] > 30

    # Custom separator and capitalization
    res2 = generate_passphrase(
        word_count=5,
        separator="_",
        capitalize=True,
        include_number=False
    )
    words2 = res2["passphrase"].split("_")
    assert len(words2) == 5
    for w in words2:
        assert w[0].isupper()


def test_passphrase_boundary_constraints():
    """Passphrase clamps word counts between 3 and 8."""
    res_min = generate_passphrase(word_count=1)
    assert res_min["word_count"] == 3

    res_max = generate_passphrase(word_count=20)
    assert res_max["word_count"] == 8
