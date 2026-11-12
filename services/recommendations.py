"""
Security Recommendation Service.
Generates actionable, prioritized, and context-aware security guidance
based on detailed password vulnerability analysis.
"""
from typing import Dict, Any, List


def generate_recommendations(analysis: Dict[str, Any]) -> List[str]:
    """
    Generate a prioritized list of user-facing recommendation strings.
    """
    recs: List[str] = []
    length = analysis.get("length", 0)
    score = analysis.get("score", 0)
    patterns = analysis.get("patterns", {})
    
    # 1. Critical Check: Common or compromised password
    if analysis.get("is_common_password", False):
        recs.append("CRITICAL: This password is among the most commonly breached passwords worldwide. Never use it for any account.")

    # 2. Length Guidance (NIST SP 800-63B emphasizes length as the primary strength factor)
    if length < 8:
        recs.append("Significantly increase length: A password with fewer than 8 characters can be cracked almost instantly via brute-force.")
    elif length < 12:
        recs.append("Aim for at least 12–16 characters: Length exponentially expands the search space against offline attacks.")
    elif length >= 16 and score >= 80:
        recs.append("Great length: Lengthy credentials provide exponential resistance against modern GPU-accelerated hashing clusters.")

    # 3. Predictable Patterns and Keyboard Walks
    if patterns.get("has_keyboard_walk", False):
        walks = ", ".join(patterns.get("keyboard_walks", []))
        recs.append(f"Avoid keyboard walks ({walks}): Attackers use spatial pattern dictionaries to target adjacent keyboard sequences.")

    if patterns.get("has_sequence", False):
        seqs = ", ".join(patterns.get("sequences", []))
        recs.append(f"Remove sequential patterns ({seqs}): Sequential letters or numbers (like 1234 or abc) are prioritized by cracking tools.")

    if patterns.get("has_repeated_chars", False):
        recs.append("Reduce repeated characters: Successive identical characters decrease entropy without adding real security.")

    if patterns.get("has_dictionary_word", False):
        words = ", ".join(patterns.get("dictionary_words", []))
        recs.append(f"Avoid standalone dictionary words ({words}): Dictionary-based and hybrid mask attacks guess natural language words in milliseconds.")

    if patterns.get("has_year_or_date", False):
        recs.append("Avoid recognizable calendar years or dates (e.g., birth years, current year): Dates are commonly guessed in targeted social engineering attacks.")

    if patterns.get("has_leet_pattern", False):
        recs.append("Avoid simple letter-to-symbol substitutions (like '@' for 'a' or '3' for 'e'): Cracking rulesets (e.g., Hashcat rules) specifically test these permutations.")

    # 4. Character Variety (contextual)
    missing_classes = []
    if not analysis.get("has_uppercase", False):
        missing_classes.append("uppercase letters (A-Z)")
    if not analysis.get("has_lowercase", False):
        missing_classes.append("lowercase letters (a-z)")
    if not analysis.get("has_number", False):
        missing_classes.append("numbers (0-9)")
    if not analysis.get("has_special", False):
        missing_classes.append("special symbols (!@#$%)")

    if missing_classes and length < 16:
        recs.append(f"Enhance character variety: Incorporate {' and '.join(missing_classes)} to expand character pool entropy.")

    # 5. Passphrase Recommendation (NIST best practice)
    if length < 16 or score < 70:
        recs.append("Consider a multi-word passphrase: Stringing together 4 or more random, unrelated words (e.g., 'correct-horse-battery-staple') creates high entropy while remaining memorable.")

    # 6. Operational Security Recommendations (Universal Best Practices)
    recs.append("Use a dedicated password manager: Generate and store unique, high-entropy credentials for every service without needing to memorize them.")
    recs.append("Never reuse this password across multiple services: Credential stuffing attacks test credentials leaked from one breach against hundreds of other websites.")
    recs.append("Enable Multi-Factor Authentication (MFA / 2FA): An authenticator app or hardware security key protects your account even if your password is compromised.")

    return recs


def generate_detailed_security_feedback(analysis: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Generate structured, categorized security findings for rich UI display.
    """
    findings: List[Dict[str, str]] = []
    length = analysis.get("length", 0)
    score = analysis.get("score", 0)
    patterns = analysis.get("patterns", {})

    # Status badges and feedback cards
    if analysis.get("is_common_password", False):
        findings.append({
            "category": "High Vulnerability",
            "severity": "danger",
            "title": "Known Compromised Password",
            "description": "This password appears verbatim in public leak dictionaries and is checked first by automated credential stuffing bots."
        })

    if length < 8:
        findings.append({
            "category": "Length Risk",
            "severity": "danger",
            "title": "Critically Short Length",
            "description": f"Length of {length} characters allows exhaustive brute-force search within seconds on modest consumer hardware."
        })
    elif length >= 14:
        findings.append({
            "category": "Length Advantage",
            "severity": "success",
            "title": "Strong Search Space",
            "description": f"Length of {length} characters creates a combinatorially vast keyspace resistant to brute-force traversal."
        })

    if patterns.get("has_keyboard_walk", False):
        findings.append({
            "category": "Pattern Weakness",
            "severity": "warning",
            "title": "Keyboard Spatial Walk",
            "description": "Adjacent key walks (such as qwerty or asdf) are systematically checked by modern password-cracking dictionaries."
        })

    if patterns.get("has_dictionary_word", False):
        findings.append({
            "category": "Dictionary Vulnerability",
            "severity": "warning",
            "title": "Natural Language Word Detected",
            "description": "Common dictionary words render credentials vulnerable to wordlist attacks with hybrid rule mutations."
        })

    if analysis.get("entropy_bits", 0) >= 60:
        findings.append({
            "category": "Information Entropy",
            "severity": "success",
            "title": "High Information Entropy",
            "description": f"Theoretical entropy exceeds {analysis.get('entropy_bits', 0):.1f} bits, representing strong cryptographic uncertainty."
        })

    # Educational operational note
    findings.append({
        "category": "Defense-in-Depth",
        "severity": "info",
        "title": "Multi-Factor Authentication (MFA)",
        "description": "Even a 100-score password is vulnerable to phishing or session hijacking. MFA provides essential secondary defense."
    })

    return findings
