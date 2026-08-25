#!/usr/bin/env python3
"""
roed_s1_evaluate.py
S1 Per-Frame Anomaly Detection Evaluation — Isolation Forest
Version: 1.0.0
Author: Asim Aziz Waqas (asim.aziz@umt.edu.pk)
License: MIT

DESCRIPTION:
    Evaluates per-frame statistical anomaly detection using Isolation Forest
    on synthetic ROED CAN data. Produces confusion matrix, ROC curve,
    per-attack detection rates, and feature importance analysis.

REQUIREMENTS:
    numpy, pandas, scikit-learn, matplotlib, scipy

USAGE:
    python roed_s1_evaluate.py --input ./data/roed_combined_dataset.csv --output ./results
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, roc_auc_score, roc_curve, classification_report
from sklearn.model_selection import train_test_split
import argparse
import os
import json

# ============================================================================
# CONFIGURATION
# ============================================================================
SEED = 42
np.random.seed(SEED)

# Feature extraction for per-frame detection
FEATURE_COLS = [
    "can_id", "dlc", "inter_arrival", "payload_len"
]

# ============================================================================
# FEATURE ENGINEERING
# ============================================================================
def extract_features(df):
    """Extract per-frame statistical features."""
    features = pd.DataFrame()

    # Raw features
    features["can_id"] = df["can_id"].astype(int)
    features["dlc"] = df["dlc"].astype(int)
    features["inter_arrival"] = df["inter_arrival"].astype(float)
    features["payload_len"] = df["payload_len"].astype(int)

    # Derived features
    features["payload_zscore"] = (
        (df["payload_len"] - df["payload_len"].mean()) / df["payload_len"].std()
    ).fillna(0)

    features["ia_zscore"] = (
        (df["inter_arrival"] - df["inter_arrival"].mean()) / df["inter_arrival"].std()
    ).fillna(0)

    # CAN ID mismatch: unexpected ID appearance
    id_freq = df["can_id"].value_counts(normalize=True)
    features["id_mismatch"] = df["can_id"].apply(lambda x: 0 if id_freq.get(x, 0) > 0.05 else 1)

    # Out-of-range payload detection
    def is_out_of_range(row):
        if row["can_id"] in [0x123, 0x456] and row["payload_len"] > 0:
            return 1 if row["payload_len"] > 6 else 0
        return 0

    features["out_of_range"] = df.apply(is_out_of_range, axis=1)

    return features

# ============================================================================
# EVALUATION PIPELINE
# ============================================================================
def evaluate_s1(input_path, output_dir):
    """Execute S1 per-frame anomaly detection evaluation."""
    print("=" * 70)
    print("S1 Per-Frame Anomaly Detection — Isolation Forest")
    print("=" * 70)

    # Load data
    print(f"[1/6] Loading dataset from {input_path}...")
    df = pd.read_csv(input_path)
    print(f"      -> Loaded {len(df)} frames")

    # Feature extraction
    print("[2/6] Extracting per-frame features...")
    X = extract_features(df)
    y_true = df["label"].values
    threat_ids = df["threat_id"].fillna("Normal").values

    print(f"      -> Features: {list(X.columns)}")
    print(f"      -> Normal: {sum(y_true == 0)}, Attack: {sum(y_true == 1)}")

    # Train/test split (stratified on attack presence)
    print("[3/6] Splitting train/test (80/20)...")
    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y_true, range(len(X)), test_size=0.2, random_state=SEED,
        stratify=y_true
    )

    # Train Isolation Forest (unsupervised: train on normal only)
    print("[4/6] Training Isolation Forest...")
    X_train_normal = X_train[y_train == 0]

    clf = IsolationForest(
        n_estimators=100,
        contamination=0.1,  # Expected anomaly ratio
        random_state=SEED,
        n_jobs=-1
    )
    clf.fit(X_train_normal)

    # Predict on test set
    print("[5/6] Evaluating on test set...")
    y_pred_raw = clf.predict(X_test)
    y_pred = np.where(y_pred_raw == -1, 1, 0)  # -1 = anomaly, 1 = normal

    # Metrics
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    accuracy = (tp + tn) / (tp + tn + fp + fn)
    detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    # ROC-AUC (using decision function scores)
    scores = clf.decision_function(X_test)
    roc_auc = roc_auc_score(y_test, -scores)  # Negative because lower = more anomalous

    # Per-attack detection rates
    per_attack = {}
    for tid in ["T-01", "T-02", "T-03", "T-04", "T-06"]:
        mask = threat_ids[idx_test] == tid
        if mask.sum() > 0:
            attack_true = y_test[mask]
            attack_pred = y_pred[mask]
            attack_tp = sum((attack_true == 1) & (attack_pred == 1))
            attack_fn = sum((attack_true == 1) & (attack_pred == 0))
            per_attack[tid] = {
                "detection_rate": attack_tp / (attack_tp + attack_fn) if (attack_tp + attack_fn) > 0 else 0,
                "n_test": int(mask.sum())
            }

    # Feature importance (permutation-based)
    print("[6/6] Computing feature importance...")
    baseline_auc = roc_auc_score(y_test, -scores)
    importances = {}

    for col in X.columns:
        X_permuted = X_test.copy()
        X_permuted[col] = np.random.permutation(X_permuted[col].values)
        perm_scores = clf.decision_function(X_permuted)
        perm_auc = roc_auc_score(y_test, -perm_scores)
        importances[col] = baseline_auc - perm_auc

    # Statistical tests
    from scipy.stats import chi2_contingency, norm

    # Chi-square: attack type vs detection outcome
    contingency = np.array([
        [tp, fn],
        [fp, tn]
    ])
    chi2, chi2_p, _, _ = chi2_contingency(contingency)

    # Z-test: FPR vs 5% target
    z_stat = (fpr - 0.05) / np.sqrt((0.05 * 0.95) / (fp + tn))
    z_p = 2 * (1 - norm.cdf(abs(z_stat)))

    # Results summary
    results = {
        "overall": {
            "accuracy": round(accuracy, 4),
            "detection_rate": round(detection_rate, 4),
            "fpr": round(fpr, 4),
            "roc_auc": round(roc_auc, 4),
            "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn)
        },
        "per_attack": per_attack,
        "feature_importance": {k: round(v, 6) for k, v in importances.items()},
        "statistical_tests": {
            "chi2": {"statistic": round(chi2, 2), "p_value": f"{chi2_p:.2e}"},
            "z_test_fpr": {"statistic": round(z_stat, 2), "p_value": f"{z_p:.2e}"}
        }
    }

    # Save results
    os.makedirs(output_dir, exist_ok=True)

    with open(f"{output_dir}/s1_results.json", "w") as f:
        json.dump(results, f, indent=2)

    # Generate visualizations
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))

    # Confusion Matrix
    ax1 = axes[0, 0]
    cm = np.array([[tn, fp], [fn, tp]])
    im = ax1.imshow(cm, cmap="Blues")
    ax1.set_xticks([0, 1])
    ax1.set_yticks([0, 1])
    ax1.set_xticklabels(["Normal", "Attack"])
    ax1.set_yticklabels(["Normal", "Attack"])
    ax1.set_xlabel("Predicted")
    ax1.set_ylabel("True")
    ax1.set_title("Confusion Matrix: Isolation Forest")
    for i in range(2):
        for j in range(2):
            ax1.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", fontsize=14, fontweight="bold")

    # ROC Curve
    ax2 = axes[0, 1]
    fpr_vals, tpr_vals, _ = roc_curve(y_test, -scores)
    ax2.plot(fpr_vals, tpr_vals, "b-", linewidth=2, label=f"ROC Curve (AUC = {roc_auc:.4f})")
    ax2.plot([0, 1], [0, 1], "k--", alpha=0.5)
    ax2.set_xlabel("False Positive Rate")
    ax2.set_ylabel("True Positive Rate")
    ax2.set_title("ROC Curve: Anomaly Detection Performance")
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    # Per-Attack Detection Rate
    ax3 = axes[1, 0]
    attack_names = ["T-01\nWirelessSpoof", "T-02\nRFJamming", "T-03\nGatewayExploit",
                    "T-04\nCANReplay", "T-06\nCANFlood"]
    attack_rates = [per_attack.get(f"T-{i:02d}", {}).get("detection_rate", 0) * 100 
                    for i in [1, 2, 3, 4, 6]]
    colors = ["green" if r >= 90 else "orange" if r >= 50 else "red" for r in attack_rates]
    bars = ax3.bar(attack_names, attack_rates, color=colors, edgecolor="black")
    ax3.axhline(y=90, color="green", linestyle="--", alpha=0.5, label="Target (90%)")
    ax3.axhline(y=50, color="orange", linestyle="--", alpha=0.5, label="Minimum (50%)")
    ax3.set_ylabel("Detection Rate (%)")
    ax3.set_title("Per-Attack Detection Rate (Isolation Forest)")
    ax3.legend()
    for bar, rate in zip(bars, attack_rates):
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                f"{rate:.1f}%", ha="center", fontweight="bold")

    # Feature Importance
    ax4 = axes[1, 1]
    sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
    feat_names = [x[0] for x in sorted_imp]
    feat_vals = [x[1] for x in sorted_imp]
    ax4.barh(feat_names, feat_vals, color="steelblue", edgecolor="black")
    ax4.set_xlabel("Permutation Importance (ROC-AUC drop)")
    ax4.set_title("Feature Importance: Anomaly Detection")
    ax4.invert_yaxis()

    plt.tight_layout()
    plt.savefig(f"{output_dir}/s1_evaluation_dashboard.png", dpi=300, bbox_inches="tight")
    plt.close()

    # Print summary
    print("\n" + "=" * 70)
    print("S1 EVALUATION RESULTS")
    print("=" * 70)
    print(f"Overall Accuracy:     {accuracy*100:.2f}%")
    print(f"Detection Rate:       {detection_rate*100:.2f}%")
    print(f"False Positive Rate:  {fpr*100:.2f}%")
    print(f"ROC-AUC:              {roc_auc:.4f}")
    print(f"\nConfusion Matrix:")
    print(f"  TN: {tn:,} | FP: {fp:,}")
    print(f"  FN: {fn:,} | TP: {tp:,}")
    print(f"\nPer-Attack Detection Rates:")
    for tid, stats in per_attack.items():
        print(f"  {tid}: {stats['detection_rate']*100:.2f}% (n={stats['n_test']})")
    print(f"\nStatistical Tests:")
    print(f"  Chi-square: χ²={chi2:.2f}, p={chi2_p:.2e}")
    print(f"  Z-test (FPR<5%): Z={z_stat:.2f}, p={z_p:.2e}")
    print(f"\nResults saved to: {output_dir}/")
    print("=" * 70)

    return results

# ============================================================================
# CLI ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="S1 Per-Frame Anomaly Detection")
    parser.add_argument("--input", default="./data/roed_combined_dataset.csv", help="Input CSV")
    parser.add_argument("--output", default="./results", help="Output directory")
    args = parser.parse_args()

    evaluate_s1(args.input, args.output)
