from datetime import datetime
from database import db


class ScanHistory(db.Model):
    __tablename__ = 'scan_history'

    id           = db.Column(db.Integer,     primary_key=True)
    url          = db.Column(db.Text,         nullable=False)
    risk_score   = db.Column(db.Float,        nullable=False)
    ml_score     = db.Column(db.Float,        nullable=True)
    rule_score   = db.Column(db.Float,        nullable=True)
    prediction   = db.Column(db.String(50),   nullable=False)
    confidence   = db.Column(db.Float,        nullable=True)
    flags        = db.Column(db.JSON,         nullable=True)
    is_qr_scan   = db.Column(db.Boolean,      default=False)
    created_at   = db.Column(db.DateTime,     default=datetime.utcnow)

    # ── Feedback columns (new) ──────────────────────────────────
    # 'correct'  → user confirmed the prediction was right (👍)
    # 'wrong'    → user says prediction was wrong (👎)
    # None       → no feedback given yet
    feedback          = db.Column(db.String(10), nullable=True, default=None)
    feedback_at       = db.Column(db.DateTime,   nullable=True, default=None)

    # When feedback='wrong' we store what the user believes is the
    # true label so we can use it directly for retraining.
    # 0 = safe, 1 = phishing
    corrected_label   = db.Column(db.Integer,    nullable=True, default=None)

    def to_dict(self):
        return {
            'id':              self.id,
            'url':             self.url,
            'risk_score':      self.risk_score,
            'ml_score':        self.ml_score,
            'rule_score':      self.rule_score,
            'prediction':      self.prediction,
            'confidence':      self.confidence,
            'flags':           self.flags,
            'is_qr_scan':      self.is_qr_scan,
            'created_at':      self.created_at.isoformat(),
            'feedback':        self.feedback,
            'feedback_at':     self.feedback_at.isoformat() if self.feedback_at else None,
            'corrected_label': self.corrected_label,
        }