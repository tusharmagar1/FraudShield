"""
╔══════════════════════════════════════════════════════╗
║  FRAUDSHIELD — feedback_routes.py                    ║
║  Blueprint: /api/feedback                            ║
╚══════════════════════════════════════════════════════╝

Mount in app.py with:
    from feedback_routes import feedback_bp
    app.register_blueprint(feedback_bp)
"""

from datetime import datetime
from flask import Blueprint, request, jsonify
from database import db
from models import ScanHistory

feedback_bp = Blueprint('feedback', __name__)


# ═══════════════════════════════════════════════════
# POST /api/feedback/<scan_id>
#
# Body:
#   { "vote": "correct" }   ← thumbs up  (👍)
#   { "vote": "wrong"   }   ← thumbs down (👎)
#
# For a "wrong" vote the backend infers the corrected
# label automatically (flip of the stored prediction).
# ═══════════════════════════════════════════════════

@feedback_bp.route('/api/feedback/<int:scan_id>', methods=['POST'])
def submit_feedback(scan_id):

    scan = ScanHistory.query.get(scan_id)

    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    body = request.get_json(silent=True) or {}
    vote = (body.get('vote') or '').strip().lower()

    if vote not in ('correct', 'wrong'):
        return jsonify({
            'error': "vote must be 'correct' or 'wrong'"
        }), 400

    # Don't let the same scan be voted on twice
    if scan.feedback is not None:
        return jsonify({
            'error': 'Feedback already submitted for this scan',
            'feedback': scan.feedback
        }), 409

    scan.feedback    = vote
    scan.feedback_at = datetime.utcnow()

    # If the user says our prediction was wrong, flip the label.
    # prediction is stored as 'phishing' or 'safe'.
    if vote == 'wrong':
        scan.corrected_label = (
            0 if scan.prediction == 'phishing' else 1
        )

    db.session.commit()

    return jsonify({
        'message':         'Feedback recorded — thank you!',
        'scan_id':         scan_id,
        'vote':            vote,
        'corrected_label': scan.corrected_label,
    })


# ═══════════════════════════════════════════════════
# GET /api/feedback/stats
# Quick summary shown on the dashboard
# ═══════════════════════════════════════════════════

@feedback_bp.route('/api/feedback/stats', methods=['GET'])
def feedback_stats():

    total   = ScanHistory.query.count()
    correct = ScanHistory.query.filter_by(feedback='correct').count()
    wrong   = ScanHistory.query.filter_by(feedback='wrong').count()
    pending = ScanHistory.query.filter_by(feedback=None).count()

    accuracy_est = (
        round(correct / (correct + wrong) * 100, 1)
        if (correct + wrong) > 0
        else None
    )

    return jsonify({
        'total_scans':          total,
        'feedback_given':       correct + wrong,
        'thumbs_up':            correct,
        'thumbs_down':          wrong,
        'awaiting_feedback':    pending,
        'user_rated_accuracy':  accuracy_est,   # e.g. 94.2 (percent)
    })
