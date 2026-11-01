"""
feature_extraction.py
Extracts URL-only features for the URLShield ML model.
All features here are computable from the URL string alone — no network calls.
These are the EXACT same features used during training (train_model.py).
"""

import math
import re
from urllib.parse import urlparse, unquote

# ---------------------------------------------------------------------------
# Static reference lists
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "signin", "webscr", "billing", "support",
    "service", "alert", "validation", "authentication", "authorize",
    "credential", "wallet", "recovery", "suspended", "locked",
    "urgent", "limited", "bonus", "prize",
]

BRAND_KEYWORDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc",
    "dhl", "fedex", "ups", "usps", "ebay", "steam", "coinbase",
    "binance", "outlook", "yahoo", "icloud",
]

SUSPICIOUS_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "pw", "top", "click",
    "link", "work", "party", "download", "zip", "review", "country",
    "kim", "science", "cricket", "win", "webcam", "faith", "loan",
    "diet", "men", "date", "bid", "stream", "trade", "space", "live",
    "monster", "buzz", "rest", "mom",
}


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_ip_address(host: str) -> int:
    """Return 1 if host is an IPv4 address, else 0."""
    ipv4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    return 1 if ipv4.match(host) else 0


def _has_punycode(host: str) -> int:
    """Return 1 if the host contains a punycode-encoded label (xn--)."""
    return 1 if "xn--" in host.lower() else 0


def _digit_ratio(s: str) -> float:
    """Ratio of digit characters to total characters."""
    if not s:
        return 0.0
    return sum(ch.isdigit() for ch in s) / len(s)


def _letter_ratio(s: str) -> float:
    """Ratio of letter characters to total characters."""
    if not s:
        return 0.0
    return sum(ch.isalpha() for ch in s) / len(s)


def extract_features(url: str) -> dict:
    """
    Extract all URL-based features used by the trained model plus
    supplementary fields used by the explanation engine.

    Returns a flat dict. Keys that match training column names are used
    directly as model inputs. Extra keys (prefixed with _) are for
    the explanation engine only.
    """
    if not isinstance(url, str):
        url = str(url)

    # Ensure scheme present for consistent parsing
    if "://" not in url:
        url_for_parse = "http://" + url
    else:
        url_for_parse = url

    parsed = urlparse(url_for_parse)
    full_url = parsed.geturl()
    lower_url = full_url.lower()

    domain = parsed.netloc or ""
    # Strip port from domain for domain-specific analysis
    domain_clean = domain.split(":")[0]
    lower_domain = domain_clean.lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # -----------------------------------------------------------------------
    # Basic length metrics
    # -----------------------------------------------------------------------
    url_length = len(full_url)
    domain_length = len(domain_clean)
    path_length = len(path)

    tld = domain_clean.split(".")[-1].lower() if "." in domain_clean else ""
    tld_length = len(tld)

    # -----------------------------------------------------------------------
    # Subdomain count
    # -----------------------------------------------------------------------
    host_parts = domain_clean.split(".")
    # Subtract 2 for domain.tld; anything beyond is subdomains
    no_of_subdomain = max(0, len(host_parts) - 2)

    # -----------------------------------------------------------------------
    # Protocol
    # -----------------------------------------------------------------------
    is_https = 1 if (parsed.scheme or "").lower() == "https" else 0

    # -----------------------------------------------------------------------
    # Character-count features (full URL)
    # -----------------------------------------------------------------------
    num_letters = sum(ch.isalpha() for ch in full_url)
    num_digits = sum(ch.isdigit() for ch in full_url)
    num_equals = full_url.count("=")
    num_qmark = full_url.count("?")
    num_amp = full_url.count("&")
    num_hyphens = full_url.count("-")
    num_dots_full = full_url.count(".")
    num_at = full_url.count("@")
    num_percent = full_url.count("%")
    num_hash = full_url.count("#")

    special_chars = sum(
        1 for ch in full_url
        if not ch.isalnum() and ch not in ":/.-_?&=#@%"
    )

    # -----------------------------------------------------------------------
    # Domain-specific counts
    # -----------------------------------------------------------------------
    domain_digits = sum(ch.isdigit() for ch in domain_clean)
    domain_dots = domain_clean.count(".")
    domain_hyphens = domain_clean.count("-")

    # -----------------------------------------------------------------------
    # URL metrics
    # -----------------------------------------------------------------------
    is_ip = _is_ip_address(domain_clean)
    norm_full_url = full_url
    norm_domain = domain_clean
    norm_no_of_subdomain = no_of_subdomain

    # -----------------------------------------------------------------------
    # Entropy features
    # -----------------------------------------------------------------------
    url_entropy = round(_shannon_entropy(norm_full_url), 4)
    domain_entropy = round(_shannon_entropy(norm_domain), 4)
    path_entropy = round(_shannon_entropy(path), 4)

    # Recompute length/letter metrics
    url_length    = len(norm_full_url)
    domain_length = len(norm_domain)
    num_letters   = sum(ch.isalpha() for ch in norm_full_url)

    # -----------------------------------------------------------------------
    # Ratio features
    # -----------------------------------------------------------------------
    digit_ratio_url = round(_digit_ratio(norm_full_url), 4)
    letter_ratio_url = round(_letter_ratio(norm_full_url), 4)

    # -----------------------------------------------------------------------
    # Security heuristics
    # -----------------------------------------------------------------------
    is_ip = _is_ip_address(domain_clean)
    has_punycode = _has_punycode(domain_clean)
    has_at_sign = 1 if num_at > 0 else 0
    has_double_slash_redirect = 1 if full_url.count("//") > 1 else 0
    has_hex_encoding = 1 if num_percent > 3 else 0  # >3 % chars suggests obfuscation
    url_depth = path.count("/")

    # -----------------------------------------------------------------------
    # Keyword signals
    # -----------------------------------------------------------------------
    suspicious_keywords_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_url]
    suspicious_keywords_count = len(suspicious_keywords_found)

    brand_keywords_found = [kw for kw in BRAND_KEYWORDS if kw in lower_url]

    # BrandInSubdomain: brand appears in subdomain or domain spoof prefix,
    # but the registered domain itself is NOT the brand.
    # E.g. "paypal-secure.verify.com" -> 1; "paypal.com" -> 0; "github.com/apple/swift" -> 0
    registered_base = host_parts[-2].lower() if len(host_parts) >= 2 else lower_domain
    subdomain_str = ".".join(host_parts[:-2]).lower() if len(host_parts) > 2 else ""

    brand_in_subdomain = 0
    for kw in BRAND_KEYWORDS:
        if kw in subdomain_str:
            brand_in_subdomain = 1
            break
        if kw in registered_base and registered_base != kw:
            brand_in_subdomain = 1
            break

    # -----------------------------------------------------------------------
    # TLD suspicion
    # -----------------------------------------------------------------------
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    return {
        # ── Model-aligned features (must match train_model.py column selection) ──
        "URLLength": url_length,
        "DomainLength": domain_length,
        "TLDLength": tld_length,
        "NoOfSubDomain": no_of_subdomain,
        "IsHTTPS": is_https,
        "NoOfLettersInURL": num_letters,
        "NoOfDegitsInURL": num_digits,
        "NoOfEqualsInURL": num_equals,
        "NoOfQMarkInURL": num_qmark,
        "NoOfAmpersandInURL": num_amp,
        "NoOfOtherSpecialCharsInURL": special_chars,
        # Advanced URL features (also model inputs)
        "URLEntropy": url_entropy,
        "DomainEntropy": domain_entropy,
        "PathEntropy": path_entropy,
        "DigitRatioInURL": digit_ratio_url,
        "LetterRatioInURL": letter_ratio_url,
        "NoOfHyphensInURL": num_hyphens,
        "NoOfDotsInURL": num_dots_full,
        "NoOfAtInURL": num_at,
        "NoOfPercentInURL": num_percent,
        "URLDepth": url_depth,
        "IsIPAddress": is_ip,
        "HasPunycode": has_punycode,
        "HasAtSign": has_at_sign,
        "HasDoubleSlashRedirect": has_double_slash_redirect,
        "HasHexEncoding": has_hex_encoding,
        "IsSuspiciousTLD": is_suspicious_tld,
        "SuspiciousKeywordCount": suspicious_keywords_count,
        "BrandInSubdomain": brand_in_subdomain,
        # ── Explanation-only fields (not model inputs, prefixed _) ──
        "_suspicious_keywords_found": suspicious_keywords_found,
        "_brand_keywords_found": brand_keywords_found,
        "_domain_digits": domain_digits,
        "_domain_dots": domain_dots,
        "_domain_hyphens": domain_hyphens,
        "_tld": tld,
        "_domain": domain_clean,
        "_path_length": path_length,
    }
