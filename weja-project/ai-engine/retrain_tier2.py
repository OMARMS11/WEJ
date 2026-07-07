#!/usr/bin/env python3
"""Retrain the Tier 2 behavioral RandomForest for the WAF.

Usage:
    python retrain_tier2.py my_normal_traffic.csv my_attack_traffic.csv [more.csv ...] \
        --out randomforest_logs.pkl [--calibrate]

Every input CSV must contain the 9 behavioral feature columns plus a `label`
column. Labels may be ints (0/1) or strings ('Benign'/'Attack', any case) —
they are normalized to the FIXED convention:

        0 = Benign        1 = Attack

The model is trained on integer labels, so model.classes_ == [0, 1] and
P(Attack) is ALWAYS predict_proba(...)[:, list(classes_).index(1)].
The Flask engine resolves that index the same way (WAF_ATTACK_LABEL=1 default).
"""

import argparse
import json
import sys

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split

# Must match BEHAVIOR_FEATURES in app.py exactly (names AND order).
FEATURES = [
    'req_count', 'iat_mean', 'iat_std', 'unique_path_ratio',
    'path_entropy_mean', 'depth_mean', 'payload_len_mean', 'payload_len_std',
    'error_rate_4xx',
]

BENIGN_ALIASES = {'0', 'benign', 'normal', 'safe', 'norm', 'human'}
ATTACK_ALIASES = {'1', 'attack', 'anomaly', 'malicious', 'bot', 'ddos', 'fuzz'}


def normalize_label(value):
    key = str(value).strip().lower()
    if key in BENIGN_ALIASES:
        return 0
    if key in ATTACK_ALIASES:
        return 1
    raise ValueError(
        f"Unrecognized label {value!r}. Use 0/'Benign' or 1/'Attack' "
        f"(edit BENIGN_ALIASES/ATTACK_ALIASES if your dataset uses other names)."
    )


def load_dataset(paths):
    frames = []
    for path in paths:
        df = pd.read_csv(path)
        missing = [c for c in FEATURES if c not in df.columns]
        if missing:
            sys.exit(f"❌ {path}: missing feature columns {missing}")
        if 'label' not in df.columns:
            sys.exit(f"❌ {path}: no 'label' column")
        df = df[FEATURES + ['label']].copy()
        df['label'] = df['label'].map(normalize_label)
        df['_source'] = path
        frames.append(df)
        counts = df['label'].value_counts().to_dict()
        print(f"[load] {path}: {len(df)} rows  (benign={counts.get(0, 0)}, attack={counts.get(1, 0)})")
    data = pd.concat(frames, ignore_index=True)
    before = len(data)
    data = data.dropna(subset=FEATURES + ['label'])
    if len(data) != before:
        print(f"[load] dropped {before - len(data)} rows with NaNs")
    return data


def threshold_sweep(y_true, p_attack):
    print("\n[threshold sweep]   thr   benign flagged (FP rate)   attacks caught (recall)")
    for thr in (0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9):
        fp = float(np.mean(p_attack[y_true == 0] > thr)) if (y_true == 0).any() else float('nan')
        tp = float(np.mean(p_attack[y_true == 1] > thr)) if (y_true == 1).any() else float('nan')
        print(f"                   {thr:.2f}        {fp:6.1%}                    {tp:6.1%}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('csvs', nargs='+', help='CSV files with the 9 features + label column')
    ap.add_argument('--out', default='randomforest_logs.pkl', help='output model path')
    ap.add_argument('--calibrate', action='store_true',
                    help='wrap the forest in CalibratedClassifierCV (sigmoid, cv=3)')
    ap.add_argument('--test-size', type=float, default=0.2)
    args = ap.parse_args()

    data = load_dataset(args.csvs)
    counts = data['label'].value_counts().to_dict()
    n_benign, n_attack = counts.get(0, 0), counts.get(1, 0)
    print(f"\n[dataset] total={len(data)}  benign={n_benign}  attack={n_attack}")
    if min(n_benign, n_attack) < 30:
        print("⚠️  Fewer than 30 rows in one class — capture more windows before trusting the metrics.")
    if n_benign and n_attack and max(n_benign, n_attack) / max(1, min(n_benign, n_attack)) > 10:
        print("⚠️  Classes are >10x imbalanced; class_weight='balanced' compensates, "
              "but consider capturing more of the minority class.")

    X = data[FEATURES]
    y = data['label'].astype(int)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=args.test_size, stratify=y, random_state=42
    )

    base = RandomForestClassifier(
        n_estimators=300,
        min_samples_leaf=3,        # smooths the vote fractions -> fewer 0.0/1.0 extremes
        class_weight='balanced',   # protects the smaller class (usually your benign set)
        random_state=42,
        n_jobs=-1,
    )

    if args.calibrate:
        model = CalibratedClassifierCV(base, method='sigmoid', cv=3)
        print("[train] RandomForest + sigmoid calibration (cv=3)")
    else:
        model = base
        print("[train] RandomForest (min_samples_leaf=3, class_weight='balanced')")

    model.fit(X_tr, y_tr)  # fit on a DataFrame so feature_names_in_ is stored

    # ---- Resolve the attack probability column FROM the model, never by assumption
    classes = list(model.classes_)
    attack_idx = classes.index(1)
    print(f"\n[classes] model.classes_ = {classes}")
    print(f"[classes] P(Attack) = predict_proba(X)[:, {attack_idx}]   <-- the only correct column")

    p_attack = model.predict_proba(X_te)[:, attack_idx]
    y_pred = (p_attack > 0.5).astype(int)

    print("\n[report] held-out test set")
    print(classification_report(y_te, y_pred, target_names=['Benign(0)', 'Attack(1)'], digits=3))
    print("[confusion matrix] rows=true, cols=pred (Benign, Attack)")
    print(confusion_matrix(y_te, y_pred))
    if len(set(y_te)) == 2:
        print(f"[AUC] {roc_auc_score(y_te, p_attack):.4f}")

    benign_p = p_attack[y_te.values == 0]
    attack_p = p_attack[y_te.values == 1]
    print(f"\n[P(attack) on TRUE BENIGN]  mean={benign_p.mean():.3f}  "
          f"p95={np.percentile(benign_p, 95):.3f}  max={benign_p.max():.3f}")
    print(f"[P(attack) on TRUE ATTACK]  mean={attack_p.mean():.3f}  "
          f"p05={np.percentile(attack_p, 5):.3f}  min={attack_p.min():.3f}")

    threshold_sweep(y_te.values, p_attack)

    # ---- Acceptance checks against the project targets
    print("\n[acceptance checks]")
    ok1 = np.percentile(benign_p, 95) < 0.20
    ok2 = np.percentile(attack_p, 5) > 0.80
    print(f"  {'PASS' if ok1 else 'WARN'}: 95% of benign windows score P(attack) < 0.20 "
          f"(p95={np.percentile(benign_p, 95):.3f})")
    print(f"  {'PASS' if ok2 else 'WARN'}: 95% of attack windows score P(attack) > 0.80 "
          f"(p05={np.percentile(attack_p, 5):.3f})")
    if not (ok1 and ok2):
        print("  -> WARN usually means the two classes overlap in feature space: capture more")
        print("     benign windows of the traffic style that fails, or re-check that attack")
        print("     rows were generated through the SAME calculate_behavioral_features pipeline.")

    joblib.dump(model, args.out)
    meta = {
        'features': FEATURES,
        'attack_label': 1,
        'attack_proba_column': attack_idx,
        'classes_': [int(c) for c in classes],
        'sklearn_version': sklearn.__version__,
        'train_rows': int(len(X_tr)),
        'test_rows': int(len(X_te)),
        'sources': args.csvs,
        'calibrated': bool(args.calibrate),
    }
    with open(args.out + '.meta.json', 'w') as f:
        json.dump(meta, f, indent=2)
    print(f"\n[saved] {args.out}  (+ {args.out}.meta.json)")
    print("[runtime] keep WAF_ATTACK_LABEL=1 (the default) in the Flask engine.")


if __name__ == '__main__':
    main()
