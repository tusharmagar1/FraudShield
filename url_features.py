import re
import math
from urllib.parse import urlparse

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
    '.click', '.link', '.pw', '.cc', '.su', '.biz', '.info',
    '.online', '.site', '.website', '.tech', '.live', '.shop',
}

# URL shorteners
SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'buff.ly', 'short.link', 'rb.gy', 'cutt.ly',
    'rebrand.ly', 'tiny.cc', 'shorte.st', 'adf.ly',
}

# Common phishing keywords
PHISHING_KEYWORDS = [
    'login', 'signin', 'account', 'update', 'secure', 'verify',
    'banking', 'paypal', 'ebay', 'amazon', 'apple', 'microsoft',
    'google', 'facebook', 'instagram', 'netflix', 'confirm',
    'password', 'credential', 'suspend', 'urgent', 'alert',
    'free', 'winner', 'prize', 'click', 'offer', 'limited',
    'bonus', 'reward', 'gift', 'claim', 'lucky',
]


def entropy(s: str) -> float:
    """Calculate Shannon entropy."""
    if not s:
        return 0.0

    freq = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in freq)



def extract_features(url: str) -> dict:
    """
    Extract consistent phishing-detection features.
    MUST match train_model.py schema.
    """

    try:
        parsed = urlparse(url if url.startswith(('http', 'https', 'ftp')) else 'http://' + url)
    except Exception:
        parsed = urlparse('http://invalid-url.com')

    scheme = parsed.scheme or ''
    netloc = parsed.netloc or ''
    hostname = parsed.hostname or netloc.split(':')[0]
    path = parsed.path or ''
    query = parsed.query or ''

    full_url = url.lower()

    # Domain parsing
    parts = hostname.split('.')
    tld = '.' + parts[-1] if len(parts) > 1 else ''
    subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
    domain_core = parts[-2] if len(parts) >= 2 else hostname

    # IP detection
    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    has_ip = int(bool(ip_pattern.match(hostname)))

    # Keyword count
    keyword_count = sum(kw in full_url for kw in PHISHING_KEYWORDS)

    # Special character count
    special_char_count = sum(full_url.count(c) for c in '@!#$%^&*()-_=+[]{}|;:,<>?~')

    features = {
        # Length features
        'url_length': len(url),
        'hostname_length': len(hostname),
        'path_length': len(path),
        'query_length': len(query),

        # Structural features
        'dot_count': url.count('.'),
        'hyphen_count': url.count('-'),
        'slash_count': url.count('/'),
        'at_symbol': int('@' in url),
        'double_slash': int('//' in path),
        'prefix_suffix': int('-' in hostname),

        # Protocol/domain features
        'is_https': int(scheme == 'https'),
        'has_ip': has_ip,
        'is_shortener': int(hostname in SHORTENERS),
        'suspicious_tld': int(tld in SUSPICIOUS_TLDS),
        'subdomain_count': len(subdomain.split('.')) if subdomain else 0,
        'domain_digit_count': sum(c.isdigit() for c in domain_core),

        # Content signals
        'keyword_count': keyword_count,
        'special_char_count': special_char_count,
        'digit_ratio': sum(c.isdigit() for c in url) / max(len(url), 1),
        'letter_ratio': sum(c.isalpha() for c in url) / max(len(url), 1),

        # Entropy
        'url_entropy': round(entropy(url), 4),
        'hostname_entropy': round(entropy(hostname), 4),

        # Misc
        'has_query': int(bool(query)),
        'num_subdomains': hostname.count('.'),
        'path_depth': path.count('/'),
    }

    return features



def get_feature_names():
    sample = extract_features('https://example.com/login?id=123')
    return list(sample.keys())