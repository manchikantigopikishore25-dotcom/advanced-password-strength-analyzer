"""
Cryptographically Secure Password and Passphrase Generator.
Utilizes Python's `secrets` module (SystemRandom) backed by OS entropy
(CryptGenRandom / getrandom), ensuring resistance to statistical prediction.

Features:
- Character category enforcement (uppercase, lowercase, digits, symbols).
- Ambiguous character filtering (e.g., 'O', '0', 'I', '1', 'l', '|').
- Fisher-Yates cryptographic shuffle using secrets.randbelow.
- Diceware-style multi-word passphrase generator.
- Strictly in-memory operation: Generated passwords are NEVER persisted or logged.
"""
import secrets
import string
from typing import Dict, Any, List

from .common_passwords import DICTIONARY_WORDS

# Ambiguous characters often confused in print/screen
AMBIGUOUS_CHARS = set("Il1O0|`'")

# Standard printable symbols for password generation
SAFE_SYMBOLS = "!@#$%^&*()-_=+[]{}<>;:,."


def generate_secure_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
    avoid_ambiguous: bool = False
) -> Dict[str, Any]:
    """
    Generate a cryptographically secure random password.
    
    Guarantees:
    - At least one character from each selected category is included.
    - True CSPRNG via secrets module (SystemRandom).
    - Unbiased Fisher-Yates array permutation.
    """
    # 1. Parameter Validation
    if not isinstance(length, int):
        try:
            length = int(length)
        except (ValueError, TypeError):
            length = 16

    if length < 6:
        raise ValueError("Password length must be at least 6 characters.")
    if length > 128:
        raise ValueError("Password length cannot exceed 128 characters.")

    if not any([use_upper, use_lower, use_digits, use_special]):
        raise ValueError("At least one character category must be selected.")

    # 2. Build Character Pools
    lower_pool = string.ascii_lowercase
    upper_pool = string.ascii_uppercase
    digit_pool = string.digits
    special_pool = SAFE_SYMBOLS

    if avoid_ambiguous:
        lower_pool = "".join(c for c in lower_pool if c not in AMBIGUOUS_CHARS)
        upper_pool = "".join(c for c in upper_pool if c not in AMBIGUOUS_CHARS)
        digit_pool = "".join(c for c in digit_pool if c not in AMBIGUOUS_CHARS)
        special_pool = "".join(c for c in special_pool if c not in AMBIGUOUS_CHARS)

    selected_pools: List[str] = []
    guaranteed_chars: List[str] = []

    if use_lower and lower_pool:
        selected_pools.append(lower_pool)
        guaranteed_chars.append(secrets.choice(lower_pool))

    if use_upper and upper_pool:
        selected_pools.append(upper_pool)
        guaranteed_chars.append(secrets.choice(upper_pool))

    if use_digits and digit_pool:
        selected_pools.append(digit_pool)
        guaranteed_chars.append(secrets.choice(digit_pool))

    if use_special and special_pool:
        selected_pools.append(special_pool)
        guaranteed_chars.append(secrets.choice(special_pool))

    # Combined master pool
    combined_pool = "".join(selected_pools)
    if not combined_pool:
        raise ValueError("Available character pool is empty after applying filters.")

    # 3. Fill Remainder to Reach Target Length
    remaining_length = max(0, length - len(guaranteed_chars))
    password_chars = guaranteed_chars + [secrets.choice(combined_pool) for _ in range(remaining_length)]

    # 4. Cryptographic Fisher-Yates Shuffle
    # Prevents guaranteed category characters from always clustering at indices 0..3
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    generated_string = "".join(password_chars)

    return {
        "password": generated_string,
        "length": len(generated_string),
        "entropy_bits": round(len(generated_string) * (len(combined_pool).bit_length() - 1), 1)
    }


def generate_passphrase(
    word_count: int = 4,
    separator: str = "-",
    capitalize: bool = False,
    include_number: bool = True
) -> Dict[str, Any]:
    """
    Generate a Diceware-style memorable multi-word passphrase.
    Endorsed by NIST SP 800-63B for optimal human memorability and high entropy.
    """
    if not isinstance(word_count, int):
        try:
            word_count = int(word_count)
        except (ValueError, TypeError):
            word_count = 4

    word_count = max(3, min(8, word_count))
    word_list = list(DICTIONARY_WORDS)
    
    # Securely sample random words
    chosen_words = [secrets.choice(word_list) for _ in range(word_count)]

    if capitalize:
        chosen_words = [w.capitalize() for w in chosen_words]

    if include_number:
        # Append a cryptographically random 2-digit number to the final word
        random_num = secrets.randbelow(90) + 10  # 10-99
        chosen_words[-1] = f"{chosen_words[-1]}{random_num}"

    passphrase = separator.join(chosen_words)

    # Entropy calculation for wordlist selection: word_count * log2(len(word_list))
    # For a list of ~350 words, each word adds ~8.45 bits of entropy
    import math
    entropy = round(word_count * math.log2(len(word_list)) + (math.log2(90) if include_number else 0), 1)

    return {
        "passphrase": passphrase,
        "word_count": word_count,
        "length": len(passphrase),
        "entropy_bits": entropy
    }
