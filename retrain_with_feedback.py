"""
╔══════════════════════════════════════════════════════╗
║  FRAUDSHIELD — retrain_with_feedback.py              ║
║  Retrains the model by blending the original         ║
║  synthetic dataset with user-corrected scans.        ║
╚══════════════════════════════════════════════════════╝

Run manually:
    python retrain_with_feedback.py

Or add to cron (every Sunday at 2am):
    0 2 * * 0  cd /path/to/fraudshield && python retrain_with_feedback.py >> logs/retrain.log 2>&1
"""

import os
import sys
import json
import shutil
import datetime
import numpy as np
import pandas as pd

# ── bring in the project modules ───────────────────
sys.path.insert(0, os.path.dirname(__file__))

from url_features    import extract_features
from feature_schema  import FEATURE_COLUMNS
from train_model     import (
    generate_dataset,
    train,
    save_artifacts,
    quick_test,
    features_to_array,
)

# We need the Flask app only to query the database
from app      import app
from models   import ScanHistory


# ═══════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════

# Minimum number of "wrong" votes before we bother retraining.
# Avoids over-fitting on just 1–2 corrections.
MIN_CORRECTIONS = 10

# How many times to repeat each corrected sample so it has real
# weight against the large synthetic dataset (3000+3000 rows).
CORRECTION_WEIGHT = 5

# Where to back up the old model before overwriting
BACKUP_DIR = 'model/backups'


# ═══════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════

def backup_current_model():
    """Copy current model files to a timestamped backup folder."""

    os.makedirs(BACKUP_DIR, exist_ok=True)

    ts     = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    target = os.path.join(BACKUP_DIR, ts)

    os.makedirs(target, exist_ok=True)

    for fname in ('fraud_model.pkl', 'scaler.pkl', 'feature_names.pkl'):
        src = os.path.join('model', fname)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(target, fname))

    print(f'  ✓ Backed up current model → {target}')
    return target


def load_feedback_rows():
    """
    Pull every scan where the user said our prediction was WRONG
    and return a DataFrame with url + corrected label.
    """

    with app.app_context():

        wrong_scans = (
            ScanHistory.query
            .filter_by(feedback='wrong')
            .filter(ScanHistory.corrected_label.isnot(None))
            .all()
        )

    if not wrong_scans:
        return pd.DataFrame()

    records = []

    for scan in wrong_scans:

        try:
            feats          = extract_features(scan.url)
            feats['url']   = scan.url
            feats['label'] = scan.corrected_label   # 0=safe, 1=phishing
            records.append(feats)

        except Exception as e:
            print(f'  ⚠ Skipping scan {scan.id}: {e}')

    return pd.DataFrame(records)


# ═══════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════

def main():

    print()
    print('╔══════════════════════════════════════╗')
    print('║  FraudShield — Feedback Retraining   ║')
    print('╚══════════════════════════════════════╝')
    print(f'  Started: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}')
    print()

    # ── 1. Load user corrections ──────────────────
    print('  Step 1 — Loading user-corrected scans ...')
    feedback_df = load_feedback_rows()

    n_corrections = len(feedback_df)
    print(f'  Found {n_corrections} corrected scan(s).')

    if n_corrections < MIN_CORRECTIONS:
        print(
            f'\n  ⚠ Not enough corrections yet '
            f'(need ≥ {MIN_CORRECTIONS}, have {n_corrections}).'
        )
        print('  Skipping retrain — model unchanged.')
        print()
        return

    # Show breakdown
    safe_count     = (feedback_df['label'] == 0).sum()
    phishing_count = (feedback_df['label'] == 1).sum()
    print(f'  Corrected labels → safe: {safe_count}, phishing: {phishing_count}')

    # ── 2. Build base synthetic dataset ───────────
    print()
    print('  Step 2 — Generating synthetic base dataset ...')
    base_df = generate_dataset(n_safe=3000, n_phishing=3000)

    # ── 3. Blend: repeat corrections CORRECTION_WEIGHT times ──
    print()
    print(f'  Step 3 — Blending (correction weight = ×{CORRECTION_WEIGHT}) ...')

    repeated_feedback = pd.concat(
        [feedback_df] * CORRECTION_WEIGHT,
        ignore_index=True
    )

    combined_df = pd.concat(
        [base_df, repeated_feedback],
        ignore_index=True
    )

    combined_df = combined_df.sample(
        frac=1,
        random_state=42
    ).reset_index(drop=True)

    print(f'  Combined dataset: {len(combined_df)} rows')
    print(f'    Base synthetic : {len(base_df)}')
    print(f'    Feedback (×{CORRECTION_WEIGHT}): {len(repeated_feedback)}')

    # ── 4. Back up old model ──────────────────────
    print()
    print('  Step 4 — Backing up existing model ...')
    backup_current_model()

    # ── 5. Train new model ────────────────────────
    print()
    print('  Step 5 — Training ...')
    new_model, new_scaler, feature_names = train(combined_df)

    # ── 6. Save ───────────────────────────────────
    print()
    print('  Step 6 — Saving new model ...')
    save_artifacts(new_model, new_scaler, feature_names)

    # ── 7. Quick sanity test ──────────────────────
    print()
    print('  Step 7 — Sanity check ...')
    quick_test(new_model, new_scaler, feature_names)

    # ── 8. Log summary ────────────────────────────
    summary = {
        'retrained_at':       datetime.datetime.now().isoformat(),
        'corrections_used':   n_corrections,
        'correction_weight':  CORRECTION_WEIGHT,
        'total_training_rows': len(combined_df),
    }

    os.makedirs('logs', exist_ok=True)

    log_path = 'logs/retrain_log.jsonl'

    with open(log_path, 'a') as f:
        f.write(json.dumps(summary) + '\n')

    print(f'  ✓ Log appended → {log_path}')
    print()
    print('  Retraining complete!')
    print(f'  Finished: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}')
    print()


if __name__ == '__main__':
    main()
