"""
╔══════════════════════════════════════════════════════╗
║         FRAUDSHIELD — app.py                         ║
║  Flask REST API Backend                              ║
║  Run: python app.py                                  ║
╚══════════════════════════════════════════════════════╝
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

import joblib
import numpy as np
from groq import Groq

from flask import Flask, request, jsonify, send_from_directory, make_response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

try:
    from feedback_routes import feedback_bp
except (ImportError, ModuleNotFoundError):
    feedback_bp = None

from database import db
from models import ScanHistory

from url_features import extract_features
from train_model import features_to_array
from feature_schema import FEATURE_COLUMNS


# ═══════════════════════════════════════════════════
# FLASK SETUP
# ═══════════════════════════════════════════════════

app = Flask(
    __name__,
    static_folder='static',
    template_folder='templates'
)

CORS(app)

# Register feedback blueprint only if available
if feedback_bp is not None:
    app.register_blueprint(feedback_bp)

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fraudshield.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)


# ═══════════════════════════════════════════════════
# RATE LIMITER SETUP
# ═══════════════════════════════════════════════════

limiter = Limiter(
    # Uses the requester's IP address as the key.
    # If you're behind a proxy/nginx, use get_remote_address
    # and make sure FORWARDED_ALLOW_IPS is configured.
    key_func=get_remote_address,

    app=app,

    # Global default: applies to every route unless overridden below.
    # 200 requests/day and 50/hour is a reasonable baseline for
    # unauthenticated public APIs.
    default_limits=["200 per day", "50 per hour"],

    # Storage backend. "memory://" is fine for a single-process
    # dev server. For production with multiple workers, switch to
    # Redis: "redis://localhost:6379/0"
    storage_uri="memory://",

    # When a limit fires, return JSON instead of an HTML 429 page.
    on_breach=lambda limit: make_response(
        jsonify({
            "error": "Rate limit exceeded",
            "message": f"Too many requests. Limit: {limit.limit}",
            "retry_after": "Try again later"
        }),
        429
    )
)


# ═══════════════════════════════════════════════════
# LOAD ML MODEL
# ═══════════════════════════════════════════════════

MODEL_DIR = 'model'

try:

    model = joblib.load(
        os.path.join(MODEL_DIR, 'fraud_model.pkl')
    )

    scaler = joblib.load(
        os.path.join(MODEL_DIR, 'scaler.pkl')
    )

    feature_names = FEATURE_COLUMNS

    print("✓ ML model loaded successfully")

except Exception as e:

    print("✗ Model loading failed:", e)

    model = None
    scaler = None
    feature_names = None


# ═══════════════════════════════════════════════════
# RULE ENGINE
# ═══════════════════════════════════════════════════

def run_rule_engine(url: str, features: dict):

    flags = []

    score = 0.0

    if features['has_ip']:
        flags.append(
            "IP address used instead of domain name"
        )
        score += 0.25

    if features['suspicious_tld']:
        flags.append(
            "Suspicious top-level domain detected"
        )
        score += 0.20

    if features['is_shortener']:
        flags.append(
            "URL shortener detected"
        )
        score += 0.18

    if features['at_symbol']:
        flags.append(
            "@ symbol found in URL"
        )
        score += 0.22

    if features['keyword_count'] >= 2:
        flags.append(
            f"Multiple phishing keywords found ({features['keyword_count']})"
        )
        score += 0.15

    if features['keyword_count'] >= 4:
        flags.append(
            "Excessive phishing keywords"
        )
        score += 0.10

    if features['subdomain_count'] >= 3:
        flags.append(
            f"Too many subdomains ({features['subdomain_count']})"
        )
        score += 0.12

    if not features['is_https']:
        flags.append(
            "Website is not using HTTPS"
        )
        score += 0.08

    if features['url_length'] > 100:
        flags.append(
            f"Unusually long URL ({features['url_length']} chars)"
        )
        score += 0.07

    if features['prefix_suffix']:
        flags.append(
            "Hyphen detected in domain"
        )
        score += 0.10

    if features['domain_digit_count'] >= 3:
        flags.append(
            "Too many digits in domain"
        )
        score += 0.08

    if features['double_slash']:
        flags.append(
            "Double slash redirect pattern detected"
        )
        score += 0.06

    if features['url_entropy'] > 4.5:
        flags.append(
            f"High URL entropy ({features['url_entropy']:.2f})"
        )
        score += 0.08

    if features['special_char_count'] > 8:
        flags.append(
            f"Too many special characters ({features['special_char_count']})"
        )
        score += 0.06

    return min(score, 1.0), flags


# ═══════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════

def get_risk_level(prob: float):

    if prob >= 0.65:
        return 'HIGH'

    if prob >= 0.35:
        return 'MEDIUM'

    return 'LOW'


def blend_scores(ml_prob: float, rule_score: float):

    return round(
        (ml_prob * 0.65) + (rule_score * 0.35),
        4
    )


# ═══════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════

@app.route('/')
def index():

    return send_from_directory(
        'templates',
        'index.html'
    )


@app.route('/static/<path:filename>')
def static_files(filename):

    return send_from_directory(
        'static',
        filename
    )


# ═══════════════════════════════════════════════════
# URL ANALYSIS
# ═══════════════════════════════════════════════════

@app.route('/api/analyze/url', methods=['POST'])
@limiter.limit("30 per minute")   # ← tightest limit: main scan endpoint
@limiter.limit("300 per day")     # ← daily cap per IP
def analyze_url():

    body = request.get_json(silent=True) or {}

    url = (body.get('url') or '').strip()

    if not url:
        return jsonify({
            'error': 'URL is required'
        }), 400

    if model is None:
        return jsonify({
            'error': 'Model not loaded'
        }), 503

    try:

        # FEATURE EXTRACTION
        features = extract_features(url)

        arr = features_to_array(
            features,
            feature_names
        )

        arr_scaled = scaler.transform(arr)

        # ML PREDICTION
        prediction_probs = model.predict_proba(arr_scaled)[0]

        ml_prob = float(prediction_probs[1])

        confidence = float(np.max(prediction_probs))

        # RULE ENGINE
        rule_score, flags = run_rule_engine(
            url,
            features
        )

        # FINAL SCORE
        fraud_prob = blend_scores(
            ml_prob,
            rule_score
        )

        risk_level = get_risk_level(fraud_prob)

        prediction_label = (
            'phishing'
            if fraud_prob >= 0.5
            else 'safe'
        )

        # DISPLAY FEATURES
        display_features = {
            'url_length': features['url_length'],
            'dot_count': features['dot_count'],
            'has_https': 'Yes' if features['is_https'] else 'No',
            'has_ip': 'Yes' if features['has_ip'] else 'No',
            'shortener': 'Yes' if features['is_shortener'] else 'No',
            'keywords': features['keyword_count'],
            'entropy': features['url_entropy'],
            'subdomains': features['num_subdomains'],
        }

        # SAVE TO DATABASE
        scan = ScanHistory(
            url=url,
            risk_score=round(fraud_prob, 4),
            ml_score=round(ml_prob, 4),
            rule_score=round(rule_score, 4),
            prediction=prediction_label,
            confidence=round(confidence, 4),
            flags=flags,
            is_qr_scan=False
        )

        db.session.add(scan)

        db.session.commit()

        return jsonify({
            'id': scan.id,
            'url': url,
            'fraud_probability': round(fraud_prob, 4),
            'ml_score': round(ml_prob, 4),
            'rule_score': round(rule_score, 4),
            'confidence': round(confidence, 4),
            'risk_level': risk_level,
            'prediction': prediction_label,
            'flags': flags,
            'features': display_features,
        })

    except Exception as e:

        print("URL ANALYSIS ERROR:", str(e))

        return jsonify({
            'error': str(e)
        }), 500


# ═══════════════════════════════════════════════════
# QR ANALYSIS
# ═══════════════════════════════════════════════════

@app.route('/api/analyze/qr', methods=['POST'])
@limiter.limit("10 per minute")   # ← stricter: file uploads are more expensive
@limiter.limit("100 per day")
def analyze_qr():

    if 'file' not in request.files:
        return jsonify({
            'error': 'No file uploaded'
        }), 400

    file = request.files['file']

    try:

        from PIL import Image
        import io
        import importlib

        img_bytes = file.read()

        img = Image.open(
            io.BytesIO(img_bytes)
        )

        url = None

        # Try pyzbar
        try:

            from pyzbar.pyzbar import decode

            decoded = decode(img)

            if decoded:
                url = decoded[0].data.decode('utf-8')

        except ImportError:
            pass

        # Fallback zxingcpp
        if not url:

            try:

                zxingcpp = importlib.import_module(
                    'zxingcpp'
                )

                results = zxingcpp.read_barcodes(
                    np.array(img)
                )

                if results:
                    url = results[0].text

            except Exception:
                pass

        if not url:
            return jsonify({
                'error': 'Could not read QR code'
            }), 422

        # Forward to analyzer
        with app.test_client() as client:

            resp = client.post(
                '/api/analyze/url',
                json={'url': url},
                content_type='application/json'
            )

            return resp

    except Exception as e:

        print("QR ERROR:", str(e))

        return jsonify({
            'error': str(e)
        }), 500


# ═══════════════════════════════════════════════════
# HISTORY API
# ═══════════════════════════════════════════════════

@app.route('/api/history', methods=['GET'])
@limiter.limit("60 per minute")   # ← read-only, more generous
def get_history():

    scans = ScanHistory.query.order_by(
        ScanHistory.created_at.desc()
    ).limit(100).all()

    return jsonify([
        scan.to_dict()
        for scan in scans
    ])


# ═══════════════════════════════════════════════════
# STATS API
# ═══════════════════════════════════════════════════

@app.route('/api/stats', methods=['GET'])
@limiter.limit("60 per minute")
def get_stats():

    total_scans = ScanHistory.query.count()

    phishing_count = ScanHistory.query.filter_by(
        prediction='phishing'
    ).count()

    safe_count = ScanHistory.query.filter_by(
        prediction='safe'
    ).count()

    return jsonify({
        'total_scans': total_scans,
        'phishing_detected': phishing_count,
        'safe_urls': safe_count
    })


# ═══════════════════════════════════════════════════
# GROQ AI CHAT API
# ═══════════════════════════════════════════════════

@app.route('/api/chat', methods=['POST'])
@limiter.limit("20 per minute")   # ← each call hits the external Groq API
@limiter.limit("200 per day")
def chat():

    body = request.get_json(silent=True) or {}

    message = (body.get('message') or '').strip()

    context = body.get('context', '')

    if not message:
        return jsonify({
            'reply': 'Please send a message.'
        }), 400

    try:

        # LOAD API KEY
        api_key = os.environ.get('GROQ_API_KEY')

        print("GROQ KEY:", api_key)

        if not api_key:

            return jsonify({
                'reply': (
                    'Groq API key missing. '
                    'Check your .env file.'
                )
            }), 500

        # CREATE CLIENT
        client = Groq(
            api_key=api_key
        )

        # SYSTEM PROMPT
        system_prompt = f"""
You are FraudShield AI Security Analyst.

You specialize in:
- phishing detection
- malicious URLs
- scams
- cybersecurity
- social engineering
- web threats

Current scan context:
{context}

Rules:
- Be concise
- Be accurate
- Professional tone
"""

        # AI RESPONSE
        completion = client.chat.completions.create(
            model='llama-3.1-8b-instant',
            messages=[
                {
                    'role': 'system',
                    'content': system_prompt
                },
                {
                    'role': 'user',
                    'content': message
                }
            ],
            temperature=0.3,
            max_tokens=300
        )

        ai_reply = (
            completion
            .choices[0]
            .message
            .content
        )

        return jsonify({
            'reply': ai_reply
        })

    except Exception as e:

        print("CHAT ERROR:", str(e))

        return jsonify({
            'reply': f'AI Error: {str(e)}'
        }), 500


# ═══════════════════════════════════════════════════
# RUN SERVER
# ═══════════════════════════════════════════════════


# ═══════════════════════════════════════════════════
# SCHEMA MIGRATION
# Adds any columns the live DB is missing so the app
# never crashes after a model update.
# ═══════════════════════════════════════════════════

def _migrate_db():
    """
    Safe, additive-only migration runner.
    Each entry is (table, column, sql_type, default).
    Columns that already exist are silently skipped.
    """
    import sqlite3

    db_path = os.path.join(
        app.instance_path, 'fraudshield.db'
    )

    pending = [
        ('scan_history', 'feedback',         'TEXT',     'NULL'),
        ('scan_history', 'feedback_at',       'DATETIME', 'NULL'),
        ('scan_history', 'corrected_label',   'INTEGER',  'NULL'),
    ]

    try:
        conn = sqlite3.connect(db_path)

        existing = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(scan_history)"
            )
        }

        added = []

        for table, col, col_type, default in pending:

            if col not in existing:

                conn.execute(
                    f"ALTER TABLE {table} "
                    f"ADD COLUMN {col} {col_type} DEFAULT {default}"
                )

                added.append(col)

        conn.commit()
        conn.close()

        if added:
            print(f"✓ DB migration: added columns {added}")
        else:
            print("✓ DB schema up-to-date")

    except Exception as e:
        print(f"✗ DB migration failed: {e}")


if __name__ == '__main__':

    print()
    print("╔══════════════════════════════════════╗")
    print("║   FraudShield Server Starting       ║")
    print("║   http://127.0.0.1:5000             ║")
    print("╚══════════════════════════════════════╝")
    print()

    # Create database tables and run schema migrations
    with app.app_context():
        db.create_all()
        _migrate_db()

    app.run(
        debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true',
        port=5000,
        host='0.0.0.0'
    )