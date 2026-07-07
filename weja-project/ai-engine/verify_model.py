#!/usr/bin/env python3
"""Verify which predict_proba column of a Tier 2 pickle means "Attack".

Usage:
    python verify_model.py randomforest_logs.pkl [--attack-label 1] [--csv labeled_windows.csv]

Prints model.classes_, the resolved attack column, and the model's output on
four extreme synthetic windows (slow human vs rapid fuzzer vs flood). If the
column is mapped correctly, humans must score LOW and fuzzers HIGH on the
attack column — if it's the other way around, either the mapping or the
training data is inverted.
"""

import argparse

import joblib
import numpy as np
import pandas as pd

PROBES = {
    'human_click   (5 req, 2.2s gaps)': dict(req_count=5, iat_mean=2200.0, iat_std=900.0,
                                             unique_path_ratio=0.8, path_entropy_mean=3.4,
                                             depth_mean=2.0, payload_len_mean=14.0,
                                             payload_len_std=4.0, error_rate_4xx=0.0),
    'slow_human    (3 req, 4.5s gaps)': dict(req_count=3, iat_mean=4500.0, iat_std=1500.0,
                                             unique_path_ratio=1.0, path_entropy_mean=3.2,
                                             depth_mean=1.7, payload_len_mean=10.0,
                                             payload_len_std=2.0, error_rate_4xx=0.0),
    'fuzzer        (180 req, 55ms, 72% 4xx)': dict(req_count=180, iat_mean=55.0, iat_std=12.0,
                                                   unique_path_ratio=0.97, path_entropy_mean=4.6,
                                                   depth_mean=4.0, payload_len_mean=62.0,
                                                   payload_len_std=25.0, error_rate_4xx=0.72),
    'flood         (400 req, 20ms, 1 path)': dict(req_count=400, iat_mean=20.0, iat_std=5.0,
                                                  unique_path_ratio=0.05, path_entropy_mean=3.0,
                                                  depth_mean=1.0, payload_len_mean=8.0,
                                                  payload_len_std=0.5, error_rate_4xx=0.0),
}


def resolve_attack_index(model, attack_label):
    classes = list(model.classes_)
    print(f"model.classes_        = {classes}   (dtype: {model.classes_.dtype})")
    if attack_label in classes:
        idx = classes.index(attack_label)
    else:
        idx = next((i for i, c in enumerate(classes)
                    if str(c).strip().lower() in ('attack', 'anomaly', 'malicious', '1')), None)
        if idx is None:
            raise SystemExit(f"❌ attack label {attack_label!r} not found in classes_ {classes}")
    print(f"P(Attack) column      = predict_proba(X)[:, {idx}]  (class {classes[idx]!r})")
    return idx


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('model')
    ap.add_argument('--attack-label', default='1',
                    help="the label meaning Attack in YOUR training data (int or string)")
    ap.add_argument('--csv', help="optional labeled CSV (9 features + label) to score")
    args = ap.parse_args()

    model = joblib.load(args.model)
    try:
        attack_label = int(args.attack_label)
    except ValueError:
        attack_label = args.attack_label

    cols = list(getattr(model, 'feature_names_in_', PROBES[next(iter(PROBES))].keys()))
    print(f"feature_names_in_     = {cols}\n")
    idx = resolve_attack_index(model, attack_label)

    X = pd.DataFrame(list(PROBES.values()))[cols]
    proba = model.predict_proba(X)
    print("\nsynthetic probe                              P(attack)   verdict")
    for name, p in zip(PROBES, proba):
        pa = p[idx]
        verdict = 'ATTACK' if pa > 0.5 else 'benign'
        print(f"  {name:43s} {pa:8.3f}   {verdict}")
    print("\nExpected if healthy: humans < 0.20, fuzzer/flood > 0.80.")
    print("If it's INVERTED, your attack column or your training labels are flipped.")

    if args.csv:
        df = pd.read_csv(args.csv)
        y = df['label'].astype(str).str.strip().str.lower().map(
            lambda v: 1 if v in ('1', 'attack', 'anomaly', 'malicious') else 0)
        p = model.predict_proba(df[cols])[:, idx]
        for cls, name in ((0, 'benign'), (1, 'attack')):
            sel = p[y.values == cls]
            if len(sel):
                print(f"\n[{args.csv}] true {name}: n={len(sel)}  mean P(attack)={sel.mean():.3f}  "
                      f"p95={np.percentile(sel, 95):.3f}")


if __name__ == '__main__':
    main()
