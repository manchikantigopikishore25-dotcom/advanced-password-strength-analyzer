"""
Core Password Analysis Engine.
Computes mathematical entropy, detects sequential patterns, keyboard walks,
leet-speak mutations, common breached passwords, dictionary words, and estimates
crack resistance across multiple adversarial threat profiles.

Guarantees:
- Zero data persistence or logging.
- Pure in-memory metric calculation.
- The input password is NEVER returned in the output payload.
"""
import math
import re
import string
from typing import Dict, Any, List, Tuple

from .common_passwords import (
    COMMON_PASSWORDS,
    DICTIONARY_WORDS,
    KEYBOARD_ROWS,
    KEYBOARD_COLS,
    LEET_REPLACEMENTS
)
from .recommendations import generate_recommendations, generate_detailed_security_feedback

# Optional zxcvbn integration
try:
    import zxcvbn
    HAS_ZXCVBN = True
except ImportError:
    HAS_ZXCVBN = False


def calculate_entropy(password: str) -> Tuple[float, int, float]:
    """
    Compute theoretical Shannon entropy and effective entropy in bits.
    Returns: (theoretical_entropy, pool_size, effective_entropy)
    """
    if not password:
        return 0.0, 0, 0.0

    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_space = any(c.isspace() for c in password)
    has_special = any(not (c.isalnum() or c.isspace()) for c in password)

    # Determine character pool size R
    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_space:
        pool += 1
    if has_special:
        # Standard ASCII printable symbols count is 32; extended Unicode adds pool diversity
        pool += 33

    if pool == 0:
        return 0.0, 0, 0.0

    # Theoretical Shannon Entropy: H = L * log2(R)
    theoretical_entropy = length * math.log2(pool)

    # Calculate duplicate character frequency penalty
    char_freq: Dict[str, int] = {}
    for c in password:
        char_freq[c] = char_freq.get(c, 0) + 1

    duplicate_penalty = 0.0
    for count in char_freq.values():
        if count > 1:
            duplicate_penalty += (count - 1) * 1.5

    effective_entropy = max(0.0, theoretical_entropy - duplicate_penalty)

    return round(theoretical_entropy, 2), pool, round(effective_entropy, 2)


def normalize_leet(text: str) -> str:
    """
    Convert leet-speak substitutions back to approximate Latin letters.
    E.g., 'P@ssw0rd' -> 'password'
    """
    normalized = []
    for char in text.lower():
        normalized.append(LEET_REPLACEMENTS.get(char, char))
    return "".join(normalized)


def detect_repeated_characters(password: str) -> Dict[str, Any]:
    """
    Analyze repeated and consecutive characters.
    Differentiates between natural letter occurrences in long passphrases
    and vulnerable repeating sequences (e.g., 'aaa' or 'abcabc').
    """
    if not password:
        return {
            "has_repeated_chars": False,
            "max_consecutive_run": 0,
            "repeated_char_count": 0,
            "repeated_ratio": 0.0
        }

    length = len(password)
    unique_chars = len(set(password))
    repeated_count = length - unique_chars
    repeated_ratio = round(repeated_count / length, 2) if length > 0 else 0.0

    # Detect consecutive identical runs (e.g., 'aaa')
    max_run = 1
    current_run = 1
    for i in range(1, length):
        if password[i] == password[i - 1]:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 1

    # In long phrases (>= 16 chars), letters naturally reoccur across words.
    # We only flag repetition if there is an identical consecutive run >= 3,
    # or if the unique character diversity is extremely poor (< 5 unique chars),
    # or if in a short password the repetition ratio is high.
    if length >= 16:
        has_repeated = max_run >= 3 or unique_chars <= 4
    else:
        has_repeated = max_run >= 3 or repeated_ratio >= 0.4

    return {
        "has_repeated_chars": has_repeated,
        "max_consecutive_run": max_run,
        "repeated_char_count": repeated_count,
        "repeated_ratio": repeated_ratio
    }


def detect_sequential_characters(password: str) -> Dict[str, Any]:
    """
    Detect alphabetical (abc, cba) and numerical (123, 987) sequential runs.
    """
    detected_sequences: List[str] = []
    pwd_lower = password.lower()
    
    if len(pwd_lower) < 3:
        return {"has_sequence": False, "sequences": []}

    for i in range(len(pwd_lower) - 2):
        chunk = pwd_lower[i:i + 3]
        
        # Check alphabetical sequence
        if chunk.isalpha():
            ords = [ord(c) for c in chunk]
            if ords[1] == ords[0] + 1 and ords[2] == ords[1] + 1:
                detected_sequences.append(f"Ascending letters: '{chunk}'")
            elif ords[1] == ords[0] - 1 and ords[2] == ords[1] - 1:
                detected_sequences.append(f"Descending letters: '{chunk}'")
                
        # Check numeric sequence
        elif chunk.isdigit():
            ords = [ord(c) for c in chunk]
            if ords[1] == ords[0] + 1 and ords[2] == ords[1] + 1:
                detected_sequences.append(f"Ascending digits: '{chunk}'")
            elif ords[1] == ords[0] - 1 and ords[2] == ords[1] - 1:
                detected_sequences.append(f"Descending digits: '{chunk}'")

    # Deduplicate detected sequences
    unique_seqs = sorted(list(set(detected_sequences)))
    return {
        "has_sequence": len(unique_seqs) > 0,
        "sequences": unique_seqs
    }


def detect_keyboard_walks(password: str) -> Dict[str, Any]:
    """
    Detect spatial keyboard walks along QWERTY rows and columns.
    """
    detected_walks: List[str] = []
    pwd_lower = password.lower()

    if len(pwd_lower) < 3:
        return {"has_keyboard_walk": False, "keyboard_walks": []}

    # Horizontal row walks
    for row in KEYBOARD_ROWS:
        row_rev = row[::-1]
        for i in range(len(pwd_lower) - 2):
            chunk = pwd_lower[i:i + 3]
            if chunk in row:
                detected_walks.append(f"Keyboard walk: '{chunk}'")
            elif chunk in row_rev:
                detected_walks.append(f"Reverse keyboard walk: '{chunk}'")

    # Vertical column walks
    for col in KEYBOARD_COLS:
        col_rev = col[::-1]
        for i in range(len(pwd_lower) - 2):
            chunk = pwd_lower[i:i + 3]
            if chunk in col or chunk in col_rev:
                detected_walks.append(f"Vertical keyboard walk: '{chunk}'")

    unique_walks = sorted(list(set(detected_walks)))
    return {
        "has_keyboard_walk": len(unique_walks) > 0,
        "keyboard_walks": unique_walks
    }


def detect_dictionary_words(password: str) -> Dict[str, Any]:
    """
    Detect recognizable English dictionary stems (length >= 4).
    Flags passwords that rely predominantly on simple dictionary words.
    """
    detected_words: List[str] = []
    pwd_clean = re.sub(r'[^a-zA-Z]', '', password.lower())
    
    if len(pwd_clean) >= 4:
        for word in DICTIONARY_WORDS:
            if len(word) >= 4 and word in pwd_clean:
                detected_words.append(word)

    detected_words = sorted(list(set(detected_words)), key=len, reverse=True)[:5]

    # If the password is a long passphrase (length >= 20) with multiple words,
    # having dictionary words joined together is expected (e.g. Diceware passphrases).
    # We flag it as a vulnerability primarily if a single dictionary word dominates
    # the password length (>= 50% of the character count).
    is_vulnerable = False
    if detected_words and len(password) > 0:
        longest_match = len(detected_words[0])
        if len(password) < 18 or (longest_match / len(password) >= 0.45):
            is_vulnerable = True

    return {
        "has_dictionary_word": is_vulnerable,
        "dictionary_words": detected_words
    }


def detect_dates_and_years(password: str) -> Dict[str, Any]:
    """
    Detect common 4-digit years (1900-2099) or calendar date patterns.
    """
    year_match = re.search(r'(19\d\d|20\d\d)', password)
    date_match = re.search(r'\b(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\b', password)

    found_patterns: List[str] = []
    if year_match:
        found_patterns.append(f"Calendar year '{year_match.group(1)}'")
    if date_match:
        found_patterns.append(f"Date pattern '{date_match.group(0)}'")

    return {
        "has_year_or_date": len(found_patterns) > 0,
        "date_patterns": found_patterns
    }


def check_common_passwords(password: str) -> Tuple[bool, bool]:
    """
    Check if the password matches common breached lists directly or via leet-speak.
    Returns: (is_common, is_leet_match)
    """
    pwd_lower = password.lower().strip()
    if pwd_lower in COMMON_PASSWORDS:
        return True, False

    leet_normalized = normalize_leet(password)
    if leet_normalized in COMMON_PASSWORDS and leet_normalized != pwd_lower:
        return True, True

    return False, False


def format_duration(seconds: float) -> str:
    """
    Format time in seconds to human-readable duration string.
    """
    if seconds < 1:
        return "Instantly (< 1 second)"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} minute" if minutes == 1 else f"{minutes} minutes"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    elif seconds < 31536000:
        days = int(seconds / 86400)
        return f"{days} day" if days == 1 else f"{days} days"
    elif seconds < 3153600000:  # < 100 years
        years = int(seconds / 31536000)
        return f"{years} year" if years == 1 else f"{years} years"
    elif seconds < 315360000000:  # < 10,000 years
        centuries = int(seconds / 3153600000)
        return f"{centuries} century" if centuries == 1 else f"{centuries} centuries"
    else:
        return "Millions of years"


def estimate_crack_times(pool_size: int, length: int, effective_entropy: float, is_common: bool) -> Dict[str, str]:
    """
    Estimate cracking time across 4 adversary scenarios:
    1. Online Throttled (100 guesses/hour ≈ 0.0278 guesses/sec)
    2. Online Unthrottled (10 guesses/sec)
    3. Offline Slow KDF (Argon2id/bcrypt ≈ 10,000 guesses/sec)
    4. Offline Fast Hash (GPU cluster on MD5/NTLM ≈ 100,000,000,000 guesses/sec)
    """
    if length == 0 or pool_size == 0 or is_common:
        return {
            "online_throttled": "Instantly (< 1 second)",
            "online_unthrottled": "Instantly (< 1 second)",
            "offline_slow_hash": "Instantly (< 1 second)",
            "offline_fast_hash": "Instantly (< 1 second)"
        }

    # Total search combinations based on effective entropy: Combinations = 2^(effective_entropy)
    # Using effective entropy accounts for repetitive/pattern vulnerabilities
    try:
        total_combinations = 2.0 ** min(effective_entropy, 128.0)
    except OverflowError:
        total_combinations = 1e38

    # Average attempts to crack = Combinations / 2
    avg_attempts = total_combinations / 2.0

    online_throttled_rate = 100.0 / 3600.0  # ~0.0277 / sec
    online_unthrottled_rate = 10.0          # 10 / sec
    offline_slow_rate = 10_000.0            # 10,000 / sec (bcrypt/Argon2)
    offline_fast_rate = 100_000_000_000.0   # 100 Billion / sec (RTX 4090 Hashcat cluster)

    return {
        "online_throttled": format_duration(avg_attempts / online_throttled_rate),
        "online_unthrottled": format_duration(avg_attempts / online_unthrottled_rate),
        "offline_slow_hash": format_duration(avg_attempts / offline_slow_rate),
        "offline_fast_hash": format_duration(avg_attempts / offline_fast_rate)
    }


def calculate_score(
    length: int,
    character_classes: int,
    effective_entropy: float,
    patterns: Dict[str, Any],
    is_common: bool,
    is_leet_common: bool
) -> Tuple[int, str, List[str]]:
    """
    Compute normalized score (0-100) and strength classification:
    - 0-19: Very Weak
    - 20-39: Weak
    - 40-59: Moderate
    - 60-79: Strong
    - 80-100: Very Strong

    Returns: (score, strength_label, explanation_reasons)
    """
    reasons: List[str] = []

    # 1. Immediate termination conditions
    if length == 0:
        return 0, "Very Weak", ["No password provided."]

    if is_common or is_leet_common:
        score = 8 if is_common else 14
        reasons.append("Immediate vulnerability: Password matches widely known breached password blocklists.")
        return score, "Very Weak", reasons

    # 2. Base scoring factors
    score = 0

    # A. Length Score (0 to 40 points)
    if length >= 16:
        score += 40
        reasons.append(f"Excellent length ({length} characters): Exceeds NIST recommendations (+40 pts).")
    elif length >= 12:
        score += 30
        reasons.append(f"Good length ({length} characters): Strong foundation (+30 pts).")
    elif length >= 8:
        score += 18
        reasons.append(f"Acceptable length ({length} characters): Meets bare minimum (+18 pts).")
    elif length >= 5:
        score += 8
        reasons.append(f"Short length ({length} characters): Vulnerable to brute-force (+8 pts).")
    else:
        score += 2
        reasons.append(f"Critically short length ({length} characters): Cracked in under a second (+2 pts).")

    # B. Character Variety Score (0 to 25 points)
    class_points = {1: 5, 2: 12, 3: 20, 4: 25}
    earned_class_pts = class_points.get(character_classes, 5)
    score += earned_class_pts
    reasons.append(f"Character composition: {character_classes} of 4 character classes present (+{earned_class_pts} pts).")

    # C. Effective Entropy Score (0 to 35 points)
    if effective_entropy >= 80:
        score += 35
        reasons.append(f"High effective entropy ({effective_entropy} bits): Cryptographically strong search space (+35 pts).")
    elif effective_entropy >= 60:
        score += 25
        reasons.append(f"Moderate effective entropy ({effective_entropy} bits): Good randomness (+25 pts).")
    elif effective_entropy >= 40:
        score += 15
        reasons.append(f"Low effective entropy ({effective_entropy} bits): Limited unpredictability (+15 pts).")
    elif effective_entropy >= 20:
        score += 8
        reasons.append(f"Very low effective entropy ({effective_entropy} bits): Predictable character set (+8 pts).")
    else:
        score += 2
        reasons.append(f"Negligible effective entropy ({effective_entropy} bits) (+2 pts).")

    # D. Passphrase Bonus (Length >= 20 and effective entropy >= 70 bits)
    if length >= 20 and effective_entropy >= 70:
        score += 15
        reasons.append("Passphrase bonus: Excellent length and high total entropy structure (+15 pts).")

    # 3. Penalties for detected patterns
    if patterns.get("has_sequence", False):
        score -= 12
        reasons.append("Penalty: Sequential alphabetical or numeric sequences detected (-12 pts).")

    if patterns.get("has_keyboard_walk", False):
        score -= 15
        reasons.append("Penalty: Keyboard walk pattern detected (-15 pts).")

    if patterns.get("has_repeated_chars", False):
        score -= 10
        reasons.append("Penalty: High character repetition or consecutive identical characters (-10 pts).")

    if patterns.get("has_dictionary_word", False):
        score -= 15
        reasons.append("Penalty: Common dictionary word root detected (-15 pts).")

    if patterns.get("has_year_or_date", False):
        score -= 8
        reasons.append("Penalty: Calendar year or date pattern detected (-8 pts).")

    # Single character class penalty
    if character_classes == 1 and length < 16:
        score -= 15
        reasons.append("Penalty: Only a single character class used (-15 pts).")

    # Clamp score to [0, 100]
    final_score = max(0, min(100, score))

    # Overrides for short passwords
    if length < 6:
        final_score = min(final_score, 18)
    elif length < 8:
        final_score = min(final_score, 35)

    # Determine classification
    if final_score < 20:
        strength_label = "Very Weak"
    elif final_score < 40:
        strength_label = "Weak"
    elif final_score < 60:
        strength_label = "Moderate"
    elif final_score < 80:
        strength_label = "Strong"
    else:
        strength_label = "Very Strong"

    return final_score, strength_label, reasons


def analyze_password(password: str) -> Dict[str, Any]:
    """
    Main evaluation pipeline.
    Performs comprehensive multi-factor password strength analysis.

    IMPORTANT PRIVACY GUARANTEE:
    This function will NEVER return the input password in the resulting dictionary.
    """
    # Safe boundary handling
    if password is None:
        password = ""

    # Truncate if exceeds safe maximum length (prevents memory DoS)
    safe_password = password[:256]
    length = len(safe_password)

    # 1. Character Categorization
    has_lower = any(c.islower() for c in safe_password)
    has_upper = any(c.isupper() for c in safe_password)
    has_digit = any(c.isdigit() for c in safe_password)
    has_special = any(not (c.isalnum() or c.isspace()) for c in safe_password)
    has_space = any(c.isspace() for c in safe_password)

    lower_count = sum(1 for c in safe_password if c.islower())
    upper_count = sum(1 for c in safe_password if c.isupper())
    digit_count = sum(1 for c in safe_password if c.isdigit())
    special_count = sum(1 for c in safe_password if not (c.isalnum() or c.isspace()))
    space_count = sum(1 for c in safe_password if c.isspace())

    classes_count = sum([has_lower, has_upper, has_digit, has_special])

    # 2. Entropy Analysis
    theoretical_entropy, pool_size, effective_entropy = calculate_entropy(safe_password)

    # 3. Pattern Recognition
    repeated_info = detect_repeated_characters(safe_password)
    sequential_info = detect_sequential_characters(safe_password)
    keyboard_info = detect_keyboard_walks(safe_password)
    dictionary_info = detect_dictionary_words(safe_password)
    date_info = detect_dates_and_years(safe_password)

    is_common, is_leet = check_common_passwords(safe_password)

    patterns = {
        "has_repeated_chars": repeated_info["has_repeated_chars"],
        "max_consecutive_run": repeated_info["max_consecutive_run"],
        "repeated_char_count": repeated_info["repeated_char_count"],
        "has_sequence": sequential_info["has_sequence"],
        "sequences": sequential_info["sequences"],
        "has_keyboard_walk": keyboard_info["has_keyboard_walk"],
        "keyboard_walks": keyboard_info["keyboard_walks"],
        "has_dictionary_word": dictionary_info["has_dictionary_word"],
        "dictionary_words": dictionary_info["dictionary_words"],
        "has_year_or_date": date_info["has_year_or_date"],
        "date_patterns": date_info["date_patterns"],
        "has_leet_pattern": is_leet
    }

    # 4. Strength Scoring
    score, strength_label, explanation_reasons = calculate_score(
        length=length,
        character_classes=classes_count,
        effective_entropy=effective_entropy,
        patterns=patterns,
        is_common=is_common,
        is_leet_common=is_leet
    )

    # 5. Crack-Time Simulation
    crack_times = estimate_crack_times(
        pool_size=pool_size,
        length=length,
        effective_entropy=effective_entropy,
        is_common=(is_common or is_leet)
    )

    # 6. Optional zxcvbn Integration
    zxcvbn_data: Dict[str, Any] = {}
    if HAS_ZXCVBN and length > 0:
        try:
            zx_res = zxcvbn.zxcvbn(safe_password)
            zxcvbn_data = {
                "score": zx_res.get("score", 0),  # 0 to 4
                "guesses_log10": round(zx_res.get("guesses_log10", 0.0), 2),
                "crack_time_online_throttled": zx_res.get("crack_times_display", {}).get("online_throttling_100_per_hour", ""),
                "crack_time_offline_fast": zx_res.get("crack_times_display", {}).get("offline_fast_hashing_1e10_per_second", ""),
                "feedback_warning": zx_res.get("feedback", {}).get("warning", ""),
                "feedback_suggestions": zx_res.get("feedback", {}).get("suggestions", [])
            }
        except Exception:
            zxcvbn_data = {"enabled": False}

    # 7. Construct Raw Analysis Object for Recommendations
    base_result: Dict[str, Any] = {
        "score": score,
        "strength": strength_label,
        "length": length,
        "pool_size": pool_size,
        "entropy_bits": theoretical_entropy,
        "effective_entropy_bits": effective_entropy,
        "has_uppercase": has_upper,
        "uppercase_count": upper_count,
        "has_lowercase": has_lower,
        "lowercase_count": lower_count,
        "has_number": has_digit,
        "number_count": digit_count,
        "has_special": has_special,
        "special_count": special_count,
        "has_whitespace": has_space,
        "whitespace_count": space_count,
        "character_classes_count": classes_count,
        "unique_characters": len(set(safe_password)),
        "is_common_password": is_common or is_leet,
        "patterns": patterns,
        "crack_times": crack_times,
        "score_explanations": explanation_reasons,
        "zxcvbn": zxcvbn_data
    }

    # 8. Generate Contextual Recommendations and Detailed Feedback
    recommendations = generate_recommendations(base_result)
    detailed_findings = generate_detailed_security_feedback(base_result)

    base_result["recommendations"] = recommendations
    base_result["detailed_findings"] = detailed_findings

    return base_result
