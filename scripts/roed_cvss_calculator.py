#!/usr/bin/env python3
"""
roed_cvss_calculator.py
CVSS v3.1 Risk Scoring Calculator for ROED Threat Classes
Version: 1.0.0
Author: Asim Aziz Waqas (asim.aziz@umt.edu.pk)
License: MIT

DESCRIPTION:
    Computes CVSS v3.1 Base Scores for the six ROED threat classes (T-01 to T-06)
    using the FIRST.org specification. All metric justifications are documented.

REFERENCE:
    FIRST.org, "Common Vulnerability Scoring System v3.1: Specification Document," 2019.
    https://www.first.org/cvss/v3.1/specification-document

USAGE:
    python roed_cvss_calculator.py --threat T-01
    python roed_cvss_calculator.py --all
"""

import json
import argparse

# ============================================================================
# CVSS v3.1 BASE SCORE FORMULA (FIRST.org)
# ============================================================================

def cvss31_base_score(metrics):
    """
    Compute CVSS v3.1 Base Score from metric vector.

    Metrics dict keys:
        AV: Attack Vector [N/A/L/P]
        AC: Attack Complexity [L/H]
        PR: Privileges Required [N/L/H]
        UI: User Interaction [N/R]
        S: Scope [U/C]
        C: Confidentiality Impact [N/L/H]
        I: Integrity Impact [N/L/H]
        A: Availability Impact [N/L/H]
    """
    # Metric values
    av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_values = {"L": 0.77, "H": 0.44}
    pr_values = {"N": 0.85, "L": 0.62, "H": 0.27}  # Unchanged scope
    pr_values_changed = {"N": 0.85, "L": 0.68, "H": 0.5}  # Changed scope
    ui_values = {"N": 0.85, "R": 0.62}

    impact_values = {"N": 0, "L": 0.22, "H": 0.56}

    av = av_values[metrics["AV"]]
    ac = ac_values[metrics["AC"]]
    pr = pr_values_changed[metrics["PR"]] if metrics["S"] == "C" else pr_values[metrics["PR"]]
    ui = ui_values[metrics["UI"]]
    s = 1.0 if metrics["S"] == "U" else 1.08
    c = impact_values[metrics["C"]]
    i = impact_values[metrics["I"]]
    a = impact_values[metrics["A"]]

    # Impact Sub-Score (ISS)
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    # Impact
    if metrics["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    # Base Score
    if impact <= 0:
        base_score = 0.0
    elif metrics["S"] == "U":
        base_score = min((impact + exploitability), 10)
    else:
        base_score = min(1.08 * (impact + exploitability), 10)

    # Round to one decimal place
    base_score = round(base_score, 1)

    # Severity rating
    if base_score >= 9.0:
        severity = "Critical"
    elif base_score >= 7.0:
        severity = "High"
    elif base_score >= 4.0:
        severity = "Medium"
    elif base_score > 0:
        severity = "Low"
    else:
        severity = "None"

    return {
        "base_score": base_score,
        "severity": severity,
        "impact": round(impact, 3),
        "exploitability": round(exploitability, 3),
        "iss": round(iss, 3),
        "vector": f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"
    }

# ============================================================================
# ROED THREAT CLASS CONFIGURATIONS
# ============================================================================

THREAT_CONFIGS = {
    "T-01": {
        "name": "Wireless Spoof → CAN Injection",
        "description": "Attacker spoofs legitimate GCS wireless command and injects forged CAN frame via compromised gateway.",
        "metrics": {
            "AV": "N",   # Network: attacker can exploit wireless link remotely
            "AC": "L",   # Low: no special conditions required
            "PR": "N",   # None: no privileges needed on wireless network
            "UI": "N",   # None: fully automated attack
            "S": "C",    # Changed: wireless compromise affects CAN bus
            "C": "H",    # High: potential access to all telemetry
            "I": "H",    # High: forged actuator commands
            "A": "H"     # High: physical damage possible
        },
        "justification": "Maximum severity: network-accessible, no privileges, changed scope (wireless→CAN), full CIA impact."
    },
    "T-02": {
        "name": "RF Jamming → Control Loss",
        "description": "Attacker jams RF link between GCS and ROED, causing loss of operator control.",
        "metrics": {
            "AV": "N",   # Network: RF jamming from remote distance
            "AC": "L",   # Low: commercial jamming equipment readily available
            "PR": "N",   # None: no authentication on RF layer
            "UI": "N",   # None: automated jamming
            "S": "U",    # Unchanged: jamming affects wireless only
            "C": "N",    # None: no data disclosure
            "I": "N",    # None: no data modification
            "A": "H"     # High: complete loss of availability (control)
        },
        "justification": "Availability-only impact. No scope change (wireless layer only). Medium severity."
    },
    "T-03": {
        "name": "Gateway Exploit → Bus Takeover",
        "description": "Attacker exploits gateway firmware vulnerability to gain full CAN bus access.",
        "metrics": {
            "AV": "N",   # Network: gateway reachable via wireless
            "AC": "H",   # High: requires vulnerability discovery/exploitation
            "PR": "H",   # High: may require authenticated session or firmware access
            "UI": "N",   # None: automated exploitation
            "S": "C",    # Changed: gateway compromise → full bus access
            "C": "H",    # High: full bus sniffing capability
            "I": "H",    # High: arbitrary frame injection
            "A": "H"     # High: bus flooding capability
        },
        "justification": "High complexity and privilege requirements offset by changed scope and full CIA impact."
    },
    "T-04": {
        "name": "CAN Replay → Actuator Trigger",
        "description": "Attacker replays captured legitimate CAN frames to trigger unintended actuator behavior.",
        "metrics": {
            "AV": "L",   # Local: requires physical CAN bus access or compromised ECU
            "AC": "L",   # Low: replay requires minimal technical skill
            "PR": "N",   # None: CAN bus has no authentication
            "UI": "N",   # None: automated replay
            "S": "U",    # Unchanged: CAN bus only
            "C": "N",    # None: no data disclosure
            "I": "H",    # High: forged actuator commands via replay
            "A": "N"     # None: no availability impact
        },
        "justification": "Local access required, but no authentication on CAN. Integrity-only impact. Medium severity."
    },
    "T-05": {
        "name": "Telemetry Eavesdropping",
        "description": "Attacker passively intercepts wireless telemetry data from ROED to GCS.",
        "metrics": {
            "AV": "N",   # Network: wireless interception
            "AC": "L",   # Low: wireless sniffing with SDR
            "PR": "N",   # None: passive interception requires no privileges
            "UI": "N",   # None: passive attack
            "S": "U",    # Unchanged: information disclosure only
            "C": "H",    # High: full telemetry data exposed
            "I": "N",    # None: no modification
            "A": "N"     # None: no availability impact
        },
        "justification": "Passive attack with high confidentiality impact but no integrity/availability effects."
    },
    "T-06": {
        "name": "CAN Bus Flooding (DoS)",
        "description": "Attacker floods CAN bus with high-rate frames, causing ECU unresponsiveness.",
        "metrics": {
            "AV": "L",   # Local: requires CAN bus access
            "AC": "L",   # Low: flooding requires minimal equipment
            "PR": "N",   # None: CAN bus has no access control
            "UI": "N",   # None: automated flooding
            "S": "U",    # Unchanged: CAN bus only
            "C": "N",    # None: no data disclosure
            "I": "N",    # None: no data modification
            "A": "H"     # High: complete bus unavailability
        },
        "justification": "Local access required. Availability-only impact. Medium severity."
    }
}

# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="ROED CVSS v3.1 Calculator")
    parser.add_argument("--threat", choices=["T-01", "T-02", "T-03", "T-04", "T-05", "T-06"],
                        help="Specific threat class to score")
    parser.add_argument("--all", action="store_true", help="Score all threat classes")
    parser.add_argument("--output", default="./cvss_results.json", help="Output JSON file")
    args = parser.parse_args()

    if args.all:
        threats = list(THREAT_CONFIGS.keys())
    elif args.threat:
        threats = [args.threat]
    else:
        parser.print_help()
        return

    results = {}
    print("=" * 70)
    print("ROED CVSS v3.1 Risk Scoring — FIRST.org Calculator")
    print("=" * 70)

    for tid in threats:
        cfg = THREAT_CONFIGS[tid]
        score = cvss31_base_score(cfg["metrics"])

        results[tid] = {
            "name": cfg["name"],
            "description": cfg["description"],
            "metrics": cfg["metrics"],
            "justification": cfg["justification"],
            "cvss_score": score["base_score"],
            "severity": score["severity"],
            "vector": score["vector"],
            "impact_subscore": score["impact"],
            "exploitability_subscore": score["exploitability"],
            "iss": score["iss"]
        }

        print(f"\n{tid}: {cfg['name']}")
        print(f"  Vector:   {score['vector']}")
        print(f"  Score:    {score['base_score']} ({score['severity']})")
        print(f"  Impact:   {score['impact']:.3f} | Exploitability: {score['exploitability']:.3f}")
        print(f"  Justification: {cfg['justification']}")

    # Save results
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to: {args.output}")
    print("=" * 70)

    # Summary table
    print("\nSUMMARY TABLE:")
    print("-" * 70)
    print(f"{'ID':<6} {'Name':<35} {'Score':<8} {'Severity':<10}")
    print("-" * 70)
    for tid in threats:
        r = results[tid]
        print(f"{tid:<6} {r['name']:<35} {r['cvss_score']:<8} {r['severity']:<10}")
    print("-" * 70)

if __name__ == "__main__":
    main()
