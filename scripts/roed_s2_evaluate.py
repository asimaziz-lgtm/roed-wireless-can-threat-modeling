#!/usr/bin/env python3
"""
roed_s2_evaluate.py
S2 Temporal Sequence Anomaly Detection Evaluation
Version: 1.0.0
Author: Asim Aziz Waqas (asim.aziz@umt.edu.pk)
License: MIT

DESCRIPTION:
    Evaluates temporal sequence anomaly detection using windowed feature
    extraction with Isolation Forest and One-Class SVM on synthetic ROED data.

REQUIREMENTS:
    numpy, pandas, scikit-learn, matplotlib

USAGE:
    python roed_s2_evaluate.py --input ./data/roed_combined_dataset.csv --output ./results
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.metrics import roc_auc_score, confusion_matrix
import argparse
import os
import json

# ============================================================================
# CONFIGURATION
# ============================================================================
SEED = 42
np.random.seed(SEED)

WINDOW_SIZE = 100
STRIDE = 50
MEAN_IA = 1500          # must match MEAN_INTER_ARRIVAL in roed_synthetic_generator.py
CAN_IDS = [0x123, 0x456, 0x789, 0xABC, 0xDEF, 0x111, 0x222, 0x333]  # must match generator's CAN_IDS

# ============================================================================
# TEMPORAL FEATURE EXTRACTION
# ============================================================================
def extract_temporal_features(df, window_size=WINDOW_SIZE, stride=STRIDE):
    """Extract windowed temporal features from CAN frame sequences."""
    features = []
    labels = []
    threat_ids = []

    for start in range(0, len(df) - window_size, stride):
        window = df.iloc[start:start + window_size]

        # Inter-arrival statistics
        ia = window["inter_arrival"].values
        mean_ia = np.mean(ia)
        std_ia = np.std(ia) if np.std(ia) > 0 else 0.001
        cv_ia = std_ia / mean_ia if mean_ia > 0 else 0
        max_ia = np.max(ia)

        # Payload statistics
        pl = window["payload_len"].values
        payload_mean = np.mean(pl)
        payload_std = np.std(pl) if np.std(pl) > 0 else 0.001
        payload_range = np.max(pl) - np.min(pl)

        # Payload autocorrelation (lag-1)
        if len(pl) > 1 and np.std(pl) > 0:
            payload_autocorr = np.corrcoef(pl[:-1], pl[1:])[0, 1]
            if np.isnan(payload_autocorr):
                payload_autocorr = 0
        else:
            payload_autocorr = 0

        # CAN ID-based features
        can_ids = window["can_id"].values
        unique_ids = len(set(can_ids))
        duplicate_ratio = 1 - (unique_ids / len(can_ids)) if len(can_ids) > 0 else 0

        # Burst detection (very short inter-arrivals)
        burst_ratio = np.mean(ia < 100) if len(ia) > 0 else 0

        # Gap detection (long inter-arrivals)
        gap_ratio = np.mean(ia > 2 * MEAN_IA) if len(ia) > 0 else 0

        # Out-of-range ratio
        oor_ratio = np.mean(window.get("out_of_range", pd.Series([0]*len(window))))

        # ECU ID diversity
        ecu_id = unique_ids / len(CAN_IDS)

        features.append([
            mean_ia, std_ia, cv_ia, max_ia,
            payload_mean, payload_std, payload_range, payload_autocorr,
            duplicate_ratio, burst_ratio, gap_ratio, oor_ratio, ecu_id
        ])

        # Window label: 1 if attack frames make up >=15% of the window.
        # FIXED (audit finding, 2026-08-11): the original "any attack frame
        # present" rule mislabels almost every window as "attack" once
        # attack traffic is realistically interleaved throughout the
        # timeline (781/782 windows at attack density ~10.7%), leaving only
        # one normal window and making stratified train/test splitting and
        # ROC-AUC undefined. A 15% frame-density threshold restores a
        # meaningful anomaly-detection class balance (~22% positive windows).
        labels.append(1 if window["label"].mean() >= 0.15 else 0)

        # Dominant threat ID in window
        threats = window[window["threat_id"].notna()]["threat_id"]
        threat_ids.append(threats.mode().iloc[0] if len(threats) > 0 else "Normal")

    feature_names = [
        "mean_ia", "std_ia", "cv_ia", "max_ia",
        "payload_mean", "payload_std", "payload_range", "payload_autocorr",
        "duplicate_ratio", "burst_ratio", "gap_ratio", "oor_ratio", "ecu_id"
    ]

    return pd.DataFrame(features, columns=feature_names), np.array(labels), np.array(threat_ids)

# ============================================================================
# EVALUATION PIPELINE
# ============================================================================
def evaluate_s2(input_path, output_dir):
    """Execute S2 temporal anomaly detection evaluation."""
    print("=" * 70)
    print("S2 Temporal Sequence Anomaly Detection")
    print("=" * 70)

    # Load data
    print(f"[1/5] Loading dataset from {input_path}...")
    df = pd.read_csv(input_path)
    print(f"      -> Loaded {len(df)} frames")

    # Temporal feature extraction
    print(f"[2/5] Extracting temporal features (window={WINDOW_SIZE}, stride={STRIDE})...")
    X, y, threat_ids = extract_temporal_features(df)
    print(f"      -> {len(X)} windows generated")
    print(f"      -> Features: {list(X.columns)}")

    # Train/test split
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test, t_train, t_test = train_test_split(
        X, y, threat_ids, test_size=0.2, random_state=SEED, stratify=y
    )

    # Train on normal windows only
    X_train_normal = X_train[y_train == 0]

    # Classifier 1: Temporal Isolation Forest
    print("[3/5] Training Temporal Isolation Forest...")
    clf_if = IsolationForest(n_estimators=100, contamination=0.1, random_state=SEED)
    clf_if.fit(X_train_normal)

    # Classifier 2: One-Class SVM
    print("[4/5] Training One-Class SVM...")
    clf_svm = OneClassSVM(nu=0.1, kernel="rbf", gamma="scale")
    clf_svm.fit(X_train_normal)

    # Predictions
    print("[5/5] Evaluating classifiers...")

    # Isolation Forest predictions
    pred_if_raw = clf_if.predict(X_test)
    pred_if = np.where(pred_if_raw == -1, 1, 0)

    # One-Class SVM predictions
    pred_svm_raw = clf_svm.predict(X_test)
    pred_svm = np.where(pred_svm_raw == -1, 1, 0)

    # Metrics for both classifiers
    results = {}

    for name, pred in [("S2-IF", pred_if), ("S2-SVM", pred_svm)]:
        tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()

        accuracy = (tp + tn) / (tp + tn + fp + fn)
        detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

        # ROC-AUC using decision function
        if name == "S2-IF":
            scores = clf_if.decision_function(X_test)
        else:
            scores = clf_svm.decision_function(X_test)

        roc_auc = roc_auc_score(y_test, -scores)

        # Per-attack detection
        per_attack = {}
        for tid in ["T-01", "T-02", "T-03", "T-04", "T-06"]:
            mask = t_test == tid
            if mask.sum() > 0:
                attack_true = y_test[mask]
                attack_pred = pred[mask]
                attack_tp = sum((attack_true == 1) & (attack_pred == 1))
                attack_fn = sum((attack_true == 1) & (attack_pred == 0))
                per_attack[tid] = {
                    "detection_rate": attack_tp / (attack_tp + attack_fn) if (attack_tp + attack_fn) > 0 else 0,
                    "n_test": int(mask.sum())
                }

        results[name] = {
            "accuracy": round(accuracy, 4),
            "detection_rate": round(detection_rate, 4),
            "fpr": round(fpr, 4),
            "roc_auc": round(roc_auc, 4),
            "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
            "per_attack": per_attack
        }

    # Save results
    os.makedirs(output_dir, exist_ok=True)
    with open(f"{output_dir}/s2_results.json", "w") as f:
        json.dump(results, f, indent=2)

    # Visualizations
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))

    # Per-attack comparison (S1 vs S2-IF vs S2-SVM)
    ax1 = axes[0, 0]
    attack_names = ["T-01\nWirelessSpoof", "T-02\nRFJamming", "T-03\nGatewayExploit",
                    "T-04\nCANReplay", "T-06\nCANFlood"]
    x = np.arange(len(attack_names))
    width = 0.25

    # S1 rates for comparison, loaded from the real S1 run's output.
    # FIXED (audit finding, 2026-08-11): this was previously a hardcoded
    # mock array left over from an earlier draft, so the S1 bars in the
    # comparison dashboard did not reflect the actual S1 results file.
    s1_results_path = os.path.join(output_dir, "s1_results.json")
    if os.path.exists(s1_results_path):
        with open(s1_results_path) as f:
            _s1 = json.load(f)
        s1_rates = [_s1["per_attack"].get(f"T-{i:02d}", {}).get("detection_rate", 0) * 100
                    for i in [1, 2, 3, 4, 6]]
    else:
        print("WARNING: s1_results.json not found in output_dir; run roed_s1_evaluate.py first. "
              "Falling back to zeros rather than fabricated placeholder values.")
        s1_rates = [0.0, 0.0, 0.0, 0.0, 0.0]
    s2if_rates = [results["S2-IF"]["per_attack"].get(f"T-{i:02d}", {}).get("detection_rate", 0) * 100 
                  for i in [1, 2, 3, 4, 6]]
    s2svm_rates = [results["S2-SVM"]["per_attack"].get(f"T-{i:02d}", {}).get("detection_rate", 0) * 100 
                   for i in [1, 2, 3, 4, 6]]

    ax1.bar(x - width, s1_rates, width, label="S1: Per-Frame (IF)", color="dodgerblue", edgecolor="black")
    ax1.bar(x, s2if_rates, width, label="S2: Temporal (IF)", color="darkorange", edgecolor="black")
    ax1.bar(x + width, s2svm_rates, width, label="S2: Temporal (SVM)", color="forestgreen", edgecolor="black")
    ax1.set_ylabel("Detection Rate (%)")
    ax1.set_title("S1 vs S2: Per-Attack Detection Rate")
    ax1.set_xticks(x)
    ax1.set_xticklabels(attack_names)
    ax1.legend()
    ax1.set_ylim(0, 110)

    # ROC Curve Comparison
    ax2 = axes[0, 1]
    from sklearn.metrics import roc_curve

    for name, clf, color in [("S1", None, "dodgerblue"), ("S2-IF", clf_if, "darkorange"), ("S2-SVM", clf_svm, "forestgreen")]:
        if clf is not None:
            scores = clf.decision_function(X_test)
            fpr_vals, tpr_vals, _ = roc_curve(y_test, -scores)
            auc = roc_auc_score(y_test, -scores)
            ax2.plot(fpr_vals, tpr_vals, color=color, linewidth=2, label=f"{name} (AUC={auc:.4f})")

    ax2.plot([0, 1], [0, 1], "k--", alpha=0.5)
    ax2.set_xlabel("False Positive Rate")
    ax2.set_ylabel("True Positive Rate")
    ax2.set_title("ROC Curve Comparison (S1 vs S2)")
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    # FPR Comparison
    ax3 = axes[1, 0]
    methods = ["S1\nPer-Frame\nIF", "S2\nTemporal\nIF", "S2\nTemporal\nSVM"]
    s1_fpr = (_s1["overall"]["fpr"] * 100) if os.path.exists(s1_results_path) else 0.0
    fprs = [s1_fpr, results["S2-IF"]["fpr"]*100, results["S2-SVM"]["fpr"]*100]
    colors = ["dodgerblue", "darkorange", "red" if results["S2-SVM"]["fpr"] > 0.5 else "forestgreen"]
    bars = ax3.bar(methods, fprs, color=colors, edgecolor="black")
    ax3.axhline(y=5, color="green", linestyle="--", alpha=0.5, label="Target <5%")
    ax3.set_ylabel("False Positive Rate (%)")
    ax3.set_title("False Positive Rate Comparison")
    ax3.legend()
    for bar, rate in zip(bars, fprs):
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f"{rate:.2f}%", ha="center", fontweight="bold")

    # S2 Feature Importance (permutation for IF)
    ax4 = axes[1, 1]
    baseline_auc = roc_auc_score(y_test, -clf_if.decision_function(X_test))
    importances = {}
    for col in X.columns:
        X_perm = X_test.copy()
        X_perm[col] = np.random.permutation(X_perm[col].values)
        perm_auc = roc_auc_score(y_test, -clf_if.decision_function(X_perm))
        importances[col] = baseline_auc - perm_auc

    sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
    feat_names = [x[0] for x in sorted_imp]
    feat_vals = [x[1] for x in sorted_imp]
    ax4.barh(feat_names, feat_vals, color="steelblue", edgecolor="black")
    ax4.set_xlabel("Permutation Importance (ROC-AUC drop)")
    ax4.set_title("S2 Temporal Feature Importance")
    ax4.invert_yaxis()

    plt.tight_layout()
    plt.savefig(f"{output_dir}/s2_comparison_dashboard.png", dpi=300, bbox_inches="tight")
    plt.close()

    # Print summary
    print("\n" + "=" * 70)
    print("S2 EVALUATION RESULTS")
    print("=" * 70)
    for name, res in results.items():
        print(f"\n{name}:")
        print(f"  Accuracy:        {res['accuracy']*100:.2f}%")
        print(f"  Detection Rate:  {res['detection_rate']*100:.2f}%")
        print(f"  FPR:             {res['fpr']*100:.2f}%")
        print(f"  ROC-AUC:         {res['roc_auc']:.4f}")
        print(f"  Per-Attack:")
        for tid, stats in res["per_attack"].items():
            print(f"    {tid}: {stats['detection_rate']*100:.2f}%")
    print(f"\nResults saved to: {output_dir}/")
    print("=" * 70)

    return results

# ============================================================================
# CLI ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="S2 Temporal Anomaly Detection")
    parser.add_argument("--input", default="./data/roed_combined_dataset.csv", help="Input CSV")
    parser.add_argument("--output", default="./results", help="Output directory")
    args = parser.parse_args()

    evaluate_s2(args.input, args.output)
