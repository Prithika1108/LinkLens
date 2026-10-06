from urllib.parse import urlparse, parse_qs
import re


def analyze_url(url):
    score = 0
    reasons = []

    # Add protocol if user does not enter it
    test_url = url

    if not test_url.startswith(("http://", "https://")):
        test_url = "http://" + test_url

    try:
        parsed = urlparse(test_url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""

    except Exception:
        return {
            "score": 100,
            "risk": "HIGH RISK",
            "reasons": ["Invalid URL format"]
        }

    # ------------------------------------------------
    # 1. HTTP instead of HTTPS
    # ------------------------------------------------

    if parsed.scheme == "http":
        score += 15
        reasons.append("URL uses HTTP instead of HTTPS")

    # ------------------------------------------------
    # 2. @ symbol
    # ------------------------------------------------

    if "@" in url:
        score += 25
        reasons.append("URL contains @ character")

    # ------------------------------------------------
    # 3. IP address instead of domain
    # ------------------------------------------------

    if re.match(
        r"^(?:\d{1,3}\.){3}\d{1,3}$",
        hostname
    ):
        score += 25
        reasons.append(
            "URL uses an IP address instead of a domain name"
        )

    # ------------------------------------------------
    # 4. Suspicious keywords
    # ------------------------------------------------

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "account",
        "secure",
        "update",
        "password",
        "bank",
        "signin",
        "confirm",
        "wallet",
        "payment",
        "recover",
        "security"
    ]

    found_words = []

    lower_url = url.lower()

    for word in suspicious_words:
        if word in lower_url:
            found_words.append(word)

    if found_words:
        score += min(len(found_words) * 5, 25)

        reasons.append(
            "Suspicious keyword(s): "
            + ", ".join(found_words)
        )

    # ------------------------------------------------
    # 5. Very long URL
    # ------------------------------------------------

    if len(url) > 75:
        score += 10
        reasons.append("URL is unusually long")

    # ------------------------------------------------
    # 6. Too many subdomains
    # ------------------------------------------------

    if hostname.count(".") >= 3:
        score += 10
        reasons.append(
            "Domain contains many subdomains"
        )

    # ------------------------------------------------
    # 7. Multiple hyphens
    # ------------------------------------------------

    if hostname.count("-") >= 2:
        score += 5
        reasons.append(
            "Domain contains multiple hyphens"
        )

    # ------------------------------------------------
    # 8. Punycode domain
    # ------------------------------------------------

    if "xn--" in hostname.lower():
        score += 20
        reasons.append(
            "Domain uses Punycode encoding"
        )

    # ------------------------------------------------
    # 9. Suspicious TLD
    # ------------------------------------------------

    suspicious_tlds = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq"
    ]

    if any(hostname.lower().endswith(tld)
           for tld in suspicious_tlds):

        score += 15

        reasons.append(
            "Domain uses a commonly abused free TLD"
        )

    # ------------------------------------------------
    # 10. Excessive numbers in domain
    # ------------------------------------------------

    domain_numbers = sum(
        character.isdigit()
        for character in hostname
    )

    if domain_numbers >= 4:
        score += 10
        reasons.append(
            "Domain contains an unusual number of digits"
        )

    # ------------------------------------------------
    # 11. Suspicious double slash in path
    # ------------------------------------------------

    if "//" in path:
        score += 10
        reasons.append(
            "URL contains unusual double slash"
        )

    # ------------------------------------------------
    # 12. Too many query parameters
    # ------------------------------------------------

    parameters = parse_qs(query)

    if len(parameters) >= 5:
        score += 10
        reasons.append(
            "URL contains many query parameters"
        )

    # ------------------------------------------------
    # 13. URL shortener detection
    # ------------------------------------------------

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly"
    ]

    if hostname.lower() in shorteners:
        score += 20
        reasons.append(
            "URL uses a URL shortening service"
        )

    # ------------------------------------------------
    # 14. Excessive special characters
    # ------------------------------------------------

    special_characters = len(
        re.findall(r"[%$^*<>|]", url)
    )

    if special_characters >= 3:
        score += 10
        reasons.append(
            "URL contains several unusual special characters"
        )

    # ------------------------------------------------
    # Limit score to 100
    # ------------------------------------------------

    score = min(score, 100)

    # ------------------------------------------------
    # Risk classification
    # ------------------------------------------------

    if score >= 50:
        risk = "HIGH RISK"

    elif score >= 25:
        risk = "SUSPICIOUS"

    else:
        risk = "SAFE"

    # ------------------------------------------------
    # No suspicious features
    # ------------------------------------------------

    if not reasons:
        reasons.append(
            "No suspicious characteristics detected"
        )

    return {
        "score": score,
        "risk": risk,
        "reasons": reasons
    }