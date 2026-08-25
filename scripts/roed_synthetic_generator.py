#!/usr/bin/env python3
"""
roed_synthetic_generator.py
Synthetic CAN Data Generation Pipeline for ROED Threat Modeling
Version: 1.0.0
Author: Asim Aziz Waqas (asim.aziz@umt.edu.pk)
License: MIT (code) / CC-BY-4.0 (data)

DESCRIPTION:
    Generates synthetic CAN bus traffic with embedded attack traces for six
    threat classes (T-01 through T-06) identified in the ROED STRIDE taxonomy.
    Calibrated against ICSim and SynCAN reference statistics.

REQUIREMENTS:
    numpy, pandas, scipy

USAGE:
    python roed_synthetic_generator.py --output ./data --n_normal 35000 --n_attack 4200
"""

import os
import numpy as np
import pandas as pd
import argparse
import json
from datetime import datetime

# ============================================================================
# CONFIGURATION — Fixed Random Seeds for Reproducibility
# ============================================================================
SEED = 42
np.random.seed(SEED)

# ICSim-calibrated CAN bus parameters
CAN_IDS = [0x123, 0x456, 0x789, 0xABC, 0xDEF, 0x111, 0x222, 0x333]
ECU_MAP = {
    0x123: "Motor_Controller",
    0x456: "Steering_Servo",
    0x789: "Sensor_Aggregator",
    0xABC: "Telemetry_Unit",
    0xDEF: "Pump_Actuator",
    0x111: "Gateway_Inbound",
    0x222: "Gateway_Outbound",
    0x333: "Diagnostic"
}

# Temporal parameters (microseconds)
MEAN_INTER_ARRIVAL = 1500
STD_INTER_ARRIVAL = 450
MIN_INTER_ARRIVAL = 200
MAX_INTER_ARRIVAL = 5000

# Attack configuration
ATTACK_CONFIG = {
    "T-01": {"name": "Wireless_Spoof_CAN_Inject", "cvss": 10.0, "severity": "Critical",
             "stride": ["Spoofing", "Tampering"], "n_frames": 1033,
             "pattern": "masquerade", "target_can_id": 0x123},
    "T-02": {"name": "RF_Jamming_Control_Loss", "cvss": 6.5, "severity": "Medium",
             "stride": ["Denial_of_Service"], "n_frames": 619,
             "pattern": "absence", "target_can_id": None},
    "T-03": {"name": "Gateway_Exploit_Bus_Takeover", "cvss": 8.9, "severity": "High",
             "stride": ["Elevation_of_Privilege"], "n_frames": 876,
             "pattern": "flood_mixed", "target_can_id": 0x111},
    "T-04": {"name": "CAN_Replay_Actuator_Trigger", "cvss": 5.1, "severity": "Medium",
             "stride": ["Tampering", "Repudiation"], "n_frames": 599,
             "pattern": "replay", "target_can_id": 0x456},
    "T-05": {"name": "Telemetry_Eavesdropping", "cvss": 7.5, "severity": "High",
             "stride": ["Information_Disclosure"], "n_frames": 0,
             "pattern": "passive", "target_can_id": None},
    "T-06": {"name": "CAN_Bus_Flooding_DoS", "cvss": 4.4, "severity": "Medium",
             "stride": ["Denial_of_Service"], "n_frames": 1045,
             "pattern": "flood_pure", "target_can_id": 0x333}
}

# ============================================================================
# NORMAL TRAFFIC GENERATOR
# ============================================================================
def generate_normal_frames(n_frames, start_time=0):
    """Generate normal CAN frames calibrated to ICSim statistics."""
    frames = []
    current_time = start_time

    for i in range(n_frames):
        # Markov-chain-like CAN ID selection (hub-and-spoke)
        can_id = np.random.choice(CAN_IDS, p=[0.20, 0.15, 0.15, 0.15, 0.10, 0.10, 0.10, 0.05])

        # Payload: 0-8 bytes, context-dependent
        payload_len = np.random.randint(1, 9)
        if can_id in [0x123, 0x456]:  # Actuator commands
            payload = np.random.randint(0, 256, size=payload_len)
            payload[0] = np.clip(payload[0], 0, 180)  # Steering angle / motor speed
        elif can_id == 0x789:  # Sensor data
            payload = np.random.randint(0, 256, size=payload_len)
            payload[0] = np.clip(payload[0], 20, 100)  # Temperature range
        else:
            payload = np.random.randint(0, 256, size=payload_len)

        # Inter-arrival time (log-normal for realism)
        ia = np.random.lognormal(mean=np.log(MEAN_INTER_ARRIVAL), sigma=0.3)
        ia = np.clip(ia, MIN_INTER_ARRIVAL, MAX_INTER_ARRIVAL)
        current_time += int(ia)

        frames.append({
            "timestamp": current_time,
            "can_id": can_id,
            "dlc": payload_len,
            "payload": payload.tobytes().hex(),
            "label": 0,  # Normal
            "threat_id": None,
            "inter_arrival": int(ia)
        })

    return pd.DataFrame(frames)

# ============================================================================
# ATTACK INJECTORS
# ============================================================================
def inject_t01_masquerade(df_normal, config):
    """T-01: Wireless Spoof -> CAN Injection (masquerade attack)."""
    n = config["n_frames"]
    target_id = config["target_can_id"]
    attack_frames = []

    # Insert masquerade frames at random positions
    insert_positions = np.sort(np.random.choice(len(df_normal), size=n, replace=False))

    for pos in insert_positions:
        base_time = df_normal.iloc[pos]["timestamp"]
        # Slightly offset timing to mimic wireless latency
        timestamp = base_time + np.random.randint(50, 500)
        # Malicious payload: out-of-range actuator command
        payload = np.random.randint(0, 256, size=8)
        payload[0] = np.random.choice([200, 255])  # Dangerous steering angle

        attack_frames.append({
            "timestamp": timestamp,
            "can_id": target_id,
            "dlc": 8,
            "payload": payload.tobytes().hex(),
            "label": 1,
            "threat_id": "T-01",
            "inter_arrival": np.random.randint(200, 800)
        })

    return pd.DataFrame(attack_frames)

def inject_t02_jamming(df_normal, config):
    """T-02: RF Jamming -> Control Loss (frame absence / timing anomaly)."""
    n = config["n_frames"]
    # Jamming manifests as extended inter-arrival gaps
    # We simulate this by creating "ghost frames" that represent missing traffic
    attack_frames = []

    gap_positions = np.sort(np.random.choice(len(df_normal)-10, size=n, replace=False))

    for pos in gap_positions:
        base_time = df_normal.iloc[pos]["timestamp"]
        # Extended gap: 5-20x normal inter-arrival
        gap_multiplier = np.random.uniform(5, 20)
        extended_ia = int(MEAN_INTER_ARRIVAL * gap_multiplier)

        # Create a "gap indicator" frame (diagnostic ID with anomalous timing)
        attack_frames.append({
            "timestamp": base_time + extended_ia,
            "can_id": 0x333,  # Diagnostic ID
            "dlc": 2,
            "payload": "DEAD",  # Hex: 0xDE 0xAD (diagnostic error code)
            "label": 1,
            "threat_id": "T-02",
            "inter_arrival": extended_ia
        })

    return pd.DataFrame(attack_frames)

def inject_t03_gateway_exploit(df_normal, config):
    """T-03: Gateway Exploit -> Bus Takeover (mixed legitimate + malicious).

    FIXED (audit finding, 2026-08-11): the original implementation appended
    all n frames sequentially after df_normal["timestamp"].max(), clustering
    the entire attack at the very end of the combined timeline. That breaks
    S2's sliding-window temporal evaluation (windows in the tail region become
    single-class, collapsing cross-validation). Frames are now scattered as
    short bursts at random points across the normal-traffic time range,
    which is a more realistic model of gateway exploitation anyway (an
    attacker does not wait for all legitimate traffic to finish first).
    """
    n = config["n_frames"]
    target_id = config["target_can_id"]
    attack_frames = []

    t_min, t_max = df_normal["timestamp"].min(), df_normal["timestamp"].max()
    n_bursts = max(1, n // 15)
    burst_starts = np.sort(np.random.uniform(t_min, max(t_min + 1, t_max - 5000), size=n_bursts))
    base_count = n // n_bursts
    remainder = n - base_count * n_bursts

    for b, start in enumerate(burst_starts):
        count = base_count + (1 if b < remainder else 0)
        t = float(start)
        for _ in range(count):
            t += np.random.randint(100, 300)
            payload = np.random.randint(0, 256, size=8)
            # Privilege escalation pattern: diagnostic session control
            payload[0] = 0x10  # Session control service
            payload[1] = 0x02  # Programming session

            attack_frames.append({
                "timestamp": int(t),
                "can_id": target_id,
                "dlc": 8,
                "payload": payload.tobytes().hex(),
                "label": 1,
                "threat_id": "T-03",
                "inter_arrival": np.random.randint(100, 300)  # Faster than normal
            })

    return pd.DataFrame(attack_frames)

def inject_t04_replay(df_normal, config):
    """T-04: CAN Replay -> Actuator Trigger (replay historical valid frames)."""
    n = config["n_frames"]
    target_id = config["target_can_id"]
    attack_frames = []

    # Replay historical frames from normal traffic
    historical = df_normal[df_normal["can_id"] == target_id].sample(n=n, replace=True)

    for _, row in historical.iterrows():
        # Exact replay with slight timing offset
        attack_frames.append({
            "timestamp": row["timestamp"] + np.random.randint(100000, 500000),  # Delayed replay
            "can_id": row["can_id"],
            "dlc": row["dlc"],
            "payload": row["payload"],
            "label": 1,
            "threat_id": "T-04",
            "inter_arrival": row["inter_arrival"]
        })

    return pd.DataFrame(attack_frames)

def inject_t06_flood(df_normal, config):
    """T-06: CAN Bus Flooding DoS (high-rate injection).

    FIXED (audit finding, 2026-08-11): see inject_t03_gateway_exploit — same
    end-of-timeline clustering bug, same interleaved-burst fix applied.
    """
    n = config["n_frames"]
    target_id = config["target_can_id"]
    attack_frames = []

    t_min, t_max = df_normal["timestamp"].min(), df_normal["timestamp"].max()
    n_bursts = max(1, n // 30)
    burst_starts = np.sort(np.random.uniform(t_min, max(t_min + 1, t_max - 2000), size=n_bursts))
    base_count = n // n_bursts
    remainder = n - base_count * n_bursts

    for b, start in enumerate(burst_starts):
        count = base_count + (1 if b < remainder else 0)
        t = float(start)
        for _ in range(count):
            # Flooding: very high frequency, very short inter-arrival
            t += np.random.randint(10, 50)  # 10-50 μs (vs 1500 normal)
            payload = np.random.randint(0, 256, size=8)

            attack_frames.append({
                "timestamp": int(t),
                "can_id": target_id,
                "dlc": 8,
                "payload": payload.tobytes().hex(),
                "label": 1,
                "threat_id": "T-06",
                "inter_arrival": np.random.randint(10, 50)
            })

    return pd.DataFrame(attack_frames)

# ============================================================================
# MAIN PIPELINE
# ============================================================================
def generate_dataset(n_normal=35000, n_attack=4200, output_dir="./data"):
    """Execute full synthetic data generation pipeline."""
    print("=" * 70)
    print("ROED Synthetic CAN Data Generation Pipeline v1.0")
    print("Author: Asim Aziz Waqas | UMT Lahore")
    print("=" * 70)

    # Generate normal traffic
    print(f"[1/6] Generating {n_normal} normal CAN frames...")
    df_normal = generate_normal_frames(n_normal)
    print(f"      -> Normal traffic: {len(df_normal)} frames")

    # Generate attack traces
    print(f"[2/6] Generating attack traces ({n_attack} total frames)...")

    attacks = {}
    attacks["T-01"] = inject_t01_masquerade(df_normal, ATTACK_CONFIG["T-01"])
    attacks["T-02"] = inject_t02_jamming(df_normal, ATTACK_CONFIG["T-02"])
    attacks["T-03"] = inject_t03_gateway_exploit(df_normal, ATTACK_CONFIG["T-03"])
    attacks["T-04"] = inject_t04_replay(df_normal, ATTACK_CONFIG["T-04"])
    attacks["T-06"] = inject_t06_flood(df_normal, ATTACK_CONFIG["T-06"])

    df_attack = pd.concat(attacks.values(), ignore_index=True)
    print(f"      -> Attack frames: {len(df_attack)} frames")

    # Merge and sort by timestamp
    print("[3/6] Merging and sorting dataset...")
    df_combined = pd.concat([df_normal, df_attack], ignore_index=True)
    df_combined = df_combined.sort_values("timestamp").reset_index(drop=True)

    # Recalculate inter-arrival for combined dataset
    df_combined["inter_arrival"] = df_combined["timestamp"].diff().fillna(0).astype(int)

    # Add derived features
    print("[4/6] Computing derived features...")
    df_combined["payload_len"] = df_combined["payload"].apply(lambda x: len(x) // 2)
    df_combined["payload_entropy"] = df_combined["payload"].apply(
        lambda x: -sum((x.count(c)/len(x)) * np.log2(x.count(c)/len(x)) 
                    for c in set(x)) if len(x) > 0 else 0
    )

    # Save datasets
    print(f"[5/6] Saving datasets to {output_dir}...")
    os.makedirs(output_dir, exist_ok=True)

    df_normal.to_csv(f"{output_dir}/roed_normal_traffic.csv", index=False)
    df_attack.to_csv(f"{output_dir}/roed_attack_traffic.csv", index=False)
    df_combined.to_csv(f"{output_dir}/roed_combined_dataset.csv", index=False)

    # Save metadata
    metadata = {
        "version": "1.0.0",
        "generated": datetime.now().isoformat(),
        "seed": SEED,
        "normal_frames": len(df_normal),
        "attack_frames": len(df_attack),
        "total_frames": len(df_combined),
        "attack_distribution": {k: len(v) for k, v in attacks.items()},
        "attack_config": ATTACK_CONFIG,
        "can_ids": {hex(k): v for k, v in ECU_MAP.items()},
        "temporal_params": {
            "mean_inter_arrival": MEAN_INTER_ARRIVAL,
            "std_inter_arrival": STD_INTER_ARRIVAL
        }
    }

    with open(f"{output_dir}/metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    # Save attack manifest
    manifest = []
    for tid, cfg in ATTACK_CONFIG.items():
        manifest.append({
            "threat_id": tid,
            "name": cfg["name"],
            "cvss": cfg["cvss"],
            "severity": cfg["severity"],
            "stride": cfg["stride"],
            "n_frames": cfg["n_frames"],
            "pattern": cfg["pattern"]
        })

    pd.DataFrame(manifest).to_csv(f"{output_dir}/attack_manifest.csv", index=False)

    print(f"[6/6] Generation complete!")
    print(f"      -> Normal: {len(df_normal)} frames")
    print(f"      -> Attack: {len(df_attack)} frames")
    print(f"      -> Total:  {len(df_combined)} frames")
    print(f"      -> Files saved to: {output_dir}/")
    print("=" * 70)

    return df_combined, metadata

# ============================================================================
# CLI ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ROED Synthetic CAN Data Generator")
    parser.add_argument("--output", default="./data", help="Output directory")
    parser.add_argument("--n_normal", type=int, default=35000, help="Normal frames")
    parser.add_argument("--n_attack", type=int, default=4200, help="Attack frames")
    args = parser.parse_args()

    generate_dataset(args.n_normal, args.n_attack, args.output)
