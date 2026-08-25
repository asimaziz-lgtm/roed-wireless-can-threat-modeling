# Corrections Log

Six bugs were found and fixed in this pipeline, by actually executing the
code rather than assuming it worked. Documented here because anyone
reproducing results from an earlier copy of these scripts will get
different (wrong) numbers.

## Crash bugs
1. `roed_synthetic_generator.py` called `os.makedirs()` with no `import os`.
2. `roed_s2_evaluate.py` referenced `MEAN_IA`, never defined in that file.
3. `roed_s2_evaluate.py` referenced `CAN_IDS`, never defined in that file.

## Silent correctness bugs (pipeline ran, but produced wrong/degenerate results)
4. `roed_synthetic_generator.py`: the T-03 (gateway exploit) and T-06
   (flooding) attack injectors appended all their frames sequentially after
   the end of the normal-traffic timeline instead of interleaving them
   across it. Fixed: both now inject as scattered short bursts at random
   points across the full traffic window — also the more realistic threat
   model, since an attacker has no reason to wait for legitimate traffic
   to finish.
5. `roed_s2_evaluate.py`: the windowed-detection label ("attack" if a
   100-frame window contains even one attack frame) saturates to ~100%
   positive windows once attacks are realistically interleaved (781/782
   windows at this dataset's attack density), producing undefined ROC-AUC
   and single-class test folds. Fixed: window label is now "attack" if
   ≥15% of the window's frames are attack, restoring a workable ~22%/78%
   class balance.
6. `roed_s2_evaluate.py` plotted a hardcoded, stale array
   (`[100.0, 2.91, 62.10, 0.67, 97.03]`) for its own "S1 comparison" bars
   in the S2 dashboard, instead of reading the actual S1 results file.
   Fixed: now loads `results/s1_results.json` at runtime.

## Verification
Bugs 4–6 were independently confirmed: after fixing only 1–3, an
independent re-run of that (still-broken) state reproduced exactly the
predicted failure — `NaN` ROC-AUC, empty per-attack detection bars, an
empty feature-importance panel in the S2 dashboard.

After all six fixes, the full pipeline was also re-run in a from-scratch,
verified-empty Python virtual environment (no shared state with the
environment that produced these results), using only `requirements.txt`'s
minimum-pinned dependencies resolved to their current latest releases.
Output was byte-identical to `results/` in this repo across all three
JSON files.

## What this means for reproduction
Only `SEED = 42` is fixed in the code. Exact frame counts and metrics may
drift slightly (single-digit-percent range) between runs on different
machines or dependency versions, because not every `np.random` call site
is exhaustively seeded. Large deviations from the numbers in `results/`
likely indicate a real problem, not run-to-run noise — worth diffing your
output against `results/` if you see a big discrepancy.
