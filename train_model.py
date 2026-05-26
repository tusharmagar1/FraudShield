"""
╔══════════════════════════════════════════════════════╗
║         FRAUDSHIELD — train_model.py                 ║
║  Phishing / Fraud URL Classifier                     ║
║  Features: URL-based + rule signals                  ║
║  Model   : Random Forest (joblib saved)              ║
╚══════════════════════════════════════════════════════╝

Run:
    python train_model.py

Outputs:
    model/fraud_model.pkl      ← trained classifier
    model/scaler.pkl           ← feature scaler
    model/feature_names.pkl    ← feature name list
    model/label_encoder.pkl    ← label encoder
"""

import os
import re
import math
import pickle
import random
import warnings
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from feature_schema import FEATURE_COLUMNS

warnings.filterwarnings("ignore")

# ── sklearn ──────────────────────────────────────────
from sklearn.ensemble         import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection  import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing    import StandardScaler, LabelEncoder
from sklearn.metrics          import (classification_report, confusion_matrix,
                                      accuracy_score, roc_auc_score)
from sklearn.pipeline         import Pipeline
import joblib

# ═══════════════════════════════════════════════════
# 1.  FEATURE EXTRACTION
# ═══════════════════════════════════════════════════

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
    '.click', '.link', '.pw', '.cc', '.su', '.biz', '.info',
    '.online', '.site', '.website', '.tech', '.live', '.shop',
}

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'buff.ly', 'short.link', 'rb.gy', 'cutt.ly',
    'rebrand.ly', 'tiny.cc', 'shorte.st', 'adf.ly',
}

PHISHING_KEYWORDS = [
    'login', 'signin', 'account', 'update', 'secure', 'verify',
    'banking', 'paypal', 'ebay', 'amazon', 'apple', 'microsoft',
    'google', 'facebook', 'instagram', 'netflix', 'confirm',
    'password', 'credential', 'suspend', 'urgent', 'alert',
    'free', 'winner', 'prize', 'click', 'offer', 'limited',
    'bonus', 'reward', 'gift', 'claim', 'lucky',
]

def extract_features(url: str) -> dict:
    """
    Extract 25 numerical features from a raw URL string.
    Returns a dict  →  used both here and in app.py
    """
    try:
        parsed = urlparse(url if url.startswith(('http','ftp')) else 'http://' + url)
    except Exception:
        parsed = urlparse('http://unknown.com')

    scheme   = parsed.scheme   or ''
    netloc   = parsed.netloc   or ''
    hostname = parsed.hostname or netloc.split(':')[0]
    path     = parsed.path     or ''
    query    = parsed.query    or ''
    full     = url.lower()

    # ── domain parts ──────────────────────────────
    parts      = hostname.split('.')
    tld        = '.' + parts[-1] if len(parts) > 1 else ''
    subdomain  = '.'.join(parts[:-2]) if len(parts) > 2 else ''
    domain_core = parts[-2] if len(parts) >= 2 else hostname

    # ── entropy helper ────────────────────────────
    def entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = [s.count(c) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in freq)

    # ── ip-address check ─────────────────────────
    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    has_ip     = int(bool(ip_pattern.match(hostname)))

    # ── keyword count ─────────────────────────────
    keyword_count = sum(kw in full for kw in PHISHING_KEYWORDS)

    # ── special chars ─────────────────────────────
    special_chars = sum(full.count(c) for c in '@!#$%^&*()-_=+[]{}|;:,<>?~')

    features = {
        # length-based
        'url_length'           : len(url),
        'hostname_length'      : len(hostname),
        'path_length'          : len(path),
        'query_length'         : len(query),

        # structural
        'dot_count'            : url.count('.'),
        'hyphen_count'         : url.count('-'),
        'slash_count'          : url.count('/'),
        'at_symbol'            : int('@' in url),
        'double_slash'         : int('//' in path),
        'prefix_suffix'        : int('-' in hostname),

        # protocol / domain
        'is_https'             : int(scheme == 'https'),
        'has_ip'               : has_ip,
        'is_shortener'         : int(hostname in SHORTENERS),
        'suspicious_tld'       : int(tld in SUSPICIOUS_TLDS),
        'subdomain_count'      : len(subdomain.split('.')) if subdomain else 0,
        'domain_digit_count'   : sum(c.isdigit() for c in domain_core),

        # content signals
        'keyword_count'        : keyword_count,
        'special_char_count'   : special_chars,
        'digit_ratio'          : sum(c.isdigit() for c in url) / max(len(url), 1),
        'letter_ratio'         : sum(c.isalpha() for c in url) / max(len(url), 1),

        # entropy
        'url_entropy'          : round(entropy(url), 4),
        'hostname_entropy'     : round(entropy(hostname), 4),

        # misc
        'has_query'            : int(bool(query)),
        'num_subdomains'       : hostname.count('.'),
        'path_depth'           : path.count('/'),
    }

    return features


def features_to_array(features: dict, feature_names: list) -> np.ndarray:
    """Convert feature dict into ordered numpy array."""

    vector = []

    for feature in feature_names:
        vector.append(features.get(feature, 0))

    return np.array(vector, dtype=np.float32).reshape(1, -1)


# ═══════════════════════════════════════════════════
# 2.  SYNTHETIC DATASET GENERATION
# ═══════════════════════════════════════════════════

random.seed(42)
np.random.seed(42)

def _rand_str(length: int, chars: str = 'abcdefghijklmnopqrstuvwxyz') -> str:
    return ''.join(random.choice(chars) for _ in range(length))

def _rand_word(words) -> str:
    return random.choice(words)

LEGIT_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
    'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com',
    'wikipedia.org', 'amazon.com', 'microsoft.com', 'apple.com',
    'netflix.com', 'spotify.com', 'dropbox.com', 'medium.com',
    'nytimes.com', 'bbc.com', 'cnn.com', 'theguardian.com',
]

PHISHING_WORDS = [
    'login', 'secure', 'update', 'verify', 'account', 'banking',
    'payment', 'confirm', 'signin', 'credential', 'suspended',
]

def make_safe_url() -> str:
    domain = random.choice(LEGIT_DOMAINS)
    paths  = ['', '/about', '/home', '/products', '/contact',
              '/blog/post', '/news/today', '/help/faq']
    path   = random.choice(paths)
    scheme = random.choices(['https', 'https', 'https', 'http'], weights=[3,3,3,1])[0]
    return f"{scheme}://{domain}{path}"

def make_phishing_url() -> str:
    strategy = random.randint(0, 5)

    if strategy == 0:
        # brand-lookalike with hyphen
        brand  = random.choice(['paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix'])
        word   = random.choice(PHISHING_WORDS)
        tld    = random.choice(list(SUSPICIOUS_TLDS))
        return f"http://{brand}-{word}-{_rand_str(4)}{tld}/{_rand_str(6)}"

    elif strategy == 1:
        # IP address
        ip  = '.'.join(str(random.randint(1,255)) for _ in range(4))
        kw  = random.choice(PHISHING_KEYWORDS)
        return f"http://{ip}/{kw}/{_rand_str(8)}.html"

    elif strategy == 2:
        # long subdomain chain
        parts = [_rand_str(random.randint(4,10)) for _ in range(random.randint(3,5))]
        kw    = random.choice(PHISHING_KEYWORDS)
        tld   = random.choice(list(SUSPICIOUS_TLDS))
        return f"http://{'.'.join(parts)}{tld}/secure/{kw}?id={_rand_str(12,'0123456789abcdef')}"

    elif strategy == 3:
        # URL shortener with redirect
        shortener = random.choice(list(SHORTENERS))
        return f"http://{shortener}/{_rand_str(6)}"

    elif strategy == 4:
        # @ trick
        legit  = random.choice(LEGIT_DOMAINS)
        fake   = _rand_str(random.randint(8,14))
        tld    = random.choice(list(SUSPICIOUS_TLDS))
        return f"http://{legit}@{fake}{tld}"

    else:
        # keyword stuffing + suspicious TLD
        kws = '-'.join(random.sample(PHISHING_KEYWORDS, k=random.randint(2,4)))
        tld = random.choice(list(SUSPICIOUS_TLDS))
        return f"http://{kws}{tld}/{_rand_str(5)}/{''.join(random.choices('0123456789abcdef',k=16))}"


def generate_dataset(n_safe: int = 3000, n_phishing: int = 3000) -> pd.DataFrame:
    print(f"  Generating {n_safe} safe  URLs ...")
    safe_urls     = [make_safe_url()     for _ in range(n_safe)]
    print(f"  Generating {n_phishing} phishing URLs ...")
    phishing_urls = [make_phishing_url() for _ in range(n_phishing)]

    records = []
    for url in safe_urls:
        feats = extract_features(url)
        feats['url']   = url
        feats['label'] = 0          # 0 = safe
        records.append(feats)

    for url in phishing_urls:
        feats = extract_features(url)
        feats['url']   = url
        feats['label'] = 1          # 1 = phishing
        records.append(feats)

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


# ═══════════════════════════════════════════════════
# 3.  TRAINING
# ═══════════════════════════════════════════════════

def train(df: pd.DataFrame):
    FEATURE_COLS = FEATURE_COLUMNS

    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df['label'].values

    print(f"\n  Dataset shape : {X.shape}")
    print(f"  Safe URLs     : {(y==0).sum()}")
    print(f"  Phishing URLs : {(y==1).sum()}")

    # ── train/test split ──────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # ── scale ─────────────────────────────────────
    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # ── model ─────────────────────────────────────
    model = RandomForestClassifier(
        n_estimators   = 200,
        max_depth      = 18,
        min_samples_split = 4,
        min_samples_leaf  = 2,
        class_weight   = 'balanced',
        n_jobs         = -1,
        random_state   = 42,
    )

    print("\n  Training Random Forest ...")
    model.fit(X_train, y_train)

    # ── evaluate ──────────────────────────────────
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc    = accuracy_score(y_test, y_pred)
    auc    = roc_auc_score(y_test, y_prob)

    print(f"\n  ── Test Results ──────────────────────────")
    print(f"  Accuracy  : {acc*100:.2f}%")
    print(f"  ROC-AUC   : {auc*100:.2f}%")
    print()
    print(classification_report(y_test, y_pred, target_names=['Safe','Phishing']))

    # ── cross-validation ──────────────────────────
    print("  Cross-validation (5-fold) ...")
    cv     = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(model, X_train, y_train, cv=cv, scoring='accuracy', n_jobs=-1)
    print(f"  CV Accuracy : {scores.mean()*100:.2f}% ± {scores.std()*100:.2f}%\n")

    return model, scaler, FEATURE_COLS


# ═══════════════════════════════════════════════════
# 4.  SAVE ARTIFACTS
# ═══════════════════════════════════════════════════

def save_artifacts(model, scaler, feature_names: list):
    os.makedirs('model', exist_ok=True)

    joblib.dump(model,         'model/fraud_model.pkl')
    joblib.dump(scaler,        'model/scaler.pkl')
    joblib.dump(feature_names, 'model/feature_names.pkl')

    print("  ── Saved ─────────────────────────────────")
    print("  model/fraud_model.pkl")
    print("  model/scaler.pkl")
    print("  model/feature_names.pkl")


# ═══════════════════════════════════════════════════
# 5.  QUICK VERIFICATION
# ═══════════════════════════════════════════════════

def quick_test(model, scaler, feature_names: list):
    test_cases = [
        ("https://google.com",                         "SAFE"),
        ("https://github.com/user/repo",               "SAFE"),
        ("http://paypal-login-secure.tk/verify",       "PHISHING"),
        ("http://192.168.1.1/account/signin",          "PHISHING"),
        ("http://bit.ly/3xfree",                       "PHISHING"),
        ("http://amazon.com.secure-login.xyz/update",  "PHISHING"),
        ("https://stackoverflow.com/questions/1234",   "SAFE"),
        ("http://google.com@malicious-site.gq",        "PHISHING"),
    ]

    print("  ── Quick Tests ───────────────────────────")
    print(f"  {'URL':<50} {'Expected':<12} {'Got':<12} {'Score':>6}")
    print(f"  {'─'*50} {'─'*10} {'─'*10} {'─'*6}")

    for url, expected in test_cases:
        feats  = extract_features(url)
        arr    = features_to_array(feats, feature_names)
        arr_sc = scaler.transform(arr)
        prob   = model.predict_proba(arr_sc)[0][1]
        pred   = "PHISHING" if prob >= 0.5 else "SAFE"
        match  = "✓" if pred == expected else "✗"
        print(f"  {url[:50]:<50} {expected:<12} {pred:<12} {prob*100:>5.1f}%  {match}")

    print()


# ═══════════════════════════════════════════════════
# 6.  ENTRY POINT
# ═══════════════════════════════════════════════════

if __name__ == '__main__':
    print()
    print("╔══════════════════════════════════════╗")
    print("║   FraudShield Model Training         ║")
    print("╚══════════════════════════════════════╝")
    print()

    # check for CSV dataset (optional — uses synthetic if absent)
    CSV_PATH = 'dataset.csv'

    if os.path.exists(CSV_PATH):
        print(f"  Loading dataset from {CSV_PATH} ...")
        raw = pd.read_csv(CSV_PATH)

        # expected columns:  url , label  (0=safe, 1=phishing)
        if 'url' not in raw.columns or 'label' not in raw.columns:
            print("  ERROR: CSV must have 'url' and 'label' columns.")
            print("  Falling back to synthetic data.\n")
            df = generate_dataset()
        else:
            print(f"  Loaded {len(raw)} rows.  Extracting features ...")
            records = []
            for _, row in raw.iterrows():
                feats          = extract_features(str(row['url']))
                feats['url']   = row['url']
                feats['label'] = int(row['label'])
                records.append(feats)
            df = pd.DataFrame(records)
    else:
        print("  No dataset.csv found — generating synthetic training data ...")
        df = generate_dataset(n_safe=3000, n_phishing=3000)

    # ── train ───────────────────────────────────
    model, scaler, feature_names = train(df)

    # ── save ────────────────────────────────────
    save_artifacts(model, scaler, feature_names)

    # ── test ────────────────────────────────────
    quick_test(model, scaler, feature_names)

    print("  Done!  Start the server:  python app.py")
    print()