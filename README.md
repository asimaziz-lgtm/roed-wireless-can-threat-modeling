# ROED Wireless-CAN Threat Modeling — Reproducibility Package

Code, configuration, and results supporting the paper "Cyber-Physical
Threat Modeling for Remotely Operated Electronic Devices & Stations: A
Unified STRIDE-Based Framework with CVSS v3.1 Risk Quantification and
Reproducible Multi-Tier Empirical Validation" (Asim Aziz Waqas, submitted
to IEEE Transactions on Dependable and Secure Computing).

This repo intentionally contains **only** what's needed to reproduce the
paper's quantitative results — scripts, dependency spec, raw output, and
figures. It does not include the manuscript itself: journals don't require
(and generally don't expect) the submitted paper text on a public code
host, since submission goes through the journal's own portal. If you're
looking for the paper text, see the citation below once it's published, or
contact the author directly.

## What's here
```
scripts/          4 Python scripts: synthetic data generator, S1 (per-frame)
                   and S2 (windowed temporal) anomaly detection evaluators,
                   CVSS v3.1 calculator
results/          Raw JSON output from an actual run of the pipeline —
                   every number in the paper traces back to these files
figures/          5 PNGs generated from that same run
Dockerfile         Runs the full pipeline in a container (RUN/CMD steps
                   verified in a clean venv; the literal `docker build`
                   itself has not been tested — see note below)
CORRECTIONS.md     Six real bugs found by executing this code, and how
                   they were fixed — read this if your numbers don't match
LICENSE            MIT (code)
DATA_LICENSE.md    CC BY 4.0 (results/, figures/)
```

## Reproduce
```bash
pip install -r scripts/requirements.txt
python scripts/roed_synthetic_generator.py --output ./data --n_normal 35000 --n_attack 4200
python scripts/roed_s1_evaluate.py --input ./data/roed_combined_dataset.csv --output ./results
python scripts/roed_s2_evaluate.py --input ./data/roed_combined_dataset.csv --output ./results
python scripts/roed_cvss_calculator.py --all --output ./results/cvss_results.json
```
Expected runtime: under 5 minutes on a standard laptop, CPU only. Only
`SEED = 42` is fixed — see CORRECTIONS.md for what that does and doesn't
guarantee about exact reproducibility.

## Headline results (from results/, reproduced as above)
- S1 (per-frame, Isolation Forest): 89.56% accuracy, ROC-AUC 0.9310.
  Strong on high-amplitude attacks (wireless spoofing 100%, flooding
  98.19%, gateway exploit 94.36%); weaker on subtler ones (RF jamming
  42.34%, CAN replay 53.33%).
- S2 (windowed, 100-frame/50-stride): Isolation Forest hits 96.82%
  accuracy, ROC-AUC 1.0000 — perfect on sustained burst attacks, but
  structurally can't flag isolated single-frame attacks at the window
  level (see CORRECTIONS.md item 5 for why).
- CVSS v3.1: six threat classes scored T-01 (10.0, Critical) through
  T-02/T-03 (7.5/7.9, High) to T-04/T-06 (6.1, Medium, tied).

## Docker
```bash
docker build -t roed-repro .
docker run --rm -v $(pwd)/out:/app/results roed-repro
```
The Dockerfile's RUN/CMD commands are the exact commands verified above in
a clean environment; the container build mechanics themselves (base image
pull, layer caching) have not been separately tested in a sandboxed
environment without Docker Hub access. If you build it, a quick diff of
your output against `results/` closes that gap.

## Citation
Citation details (DOI, volume/issue) will be added here once the paper is
published. In the meantime, cite this repository directly if you use the
code:
```
Waqas, A. A. (2026). ROED Wireless-CAN Threat Modeling: Reproducibility
Package [Software]. https://github.com/asimaziz-lgtm/roed-wireless-can-threat-modeling
```

## Contact
Asim Aziz Waqas — Lecturer, Department of Computer Science, University of
Management & Technology (UMT), Lahore, Pakistan — asim.aziz@umt.edu.pk
