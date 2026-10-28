"""
report.py
=========
Measures every number and figure used in the paper directly from the code,
so the paper and the implementation agree. Writes to results/:

  summary.json             all metrics, counts and timings
  tree_rules_<dataset>.txt the trained Decision Tree as if/then rules
  fig1_accuracy_f1.png     accuracy and F1 per model
  fig2_error_rates.png     false positive / false negative rate per model
  fig3_pta_scores.png      Stage 1 score distribution with the learned threshold
  fig4_latency.png         per-session processing time
  fig5_decisions.png       what the graded response actually decided
"""

import json
import os
import time
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix

from hybrid_detector import HybridDetector
from pta.datasets import build_sdsc_dataset, build_clarknet_dataset
from pta.models_comparison import run_comparison, DeepLearningModel

OUT         = "results"
N           = 10000
TRAIN_SPLIT = 8000
DATASETS    = [("SDSC-HTTP", build_sdsc_dataset),
               ("CLARKNET-HTTP", build_clarknet_dataset)]
SHORT_NAMES = {"Hybrid PTA+DT (Ours)":             "Hybrid\n(ours)",
               "PTA Only (Praseed 2021)":          "PTA Only",
               "Random Walk (Xu et al. 2014)":     "Random\nWalk",
               "Deep Learning / MLP (Neural Net)": "MLP",
               "Rate Threshold (Baseline)":        "Rate\nThreshold"}


def _ms_per_session(fn, sessions):
    """Average wall time of fn(session), called one session at a time."""
    t0 = time.perf_counter()
    for s in sessions:
        fn(s)
    return (time.perf_counter() - t0) * 1000 / len(sessions)


def measure(name, builder):
    sessions, labels = builder(n_sessions=N)
    train_s, train_l = sessions[:TRAIN_SPLIT], labels[:TRAIN_SPLIT]
    test_s,  test_l  = sessions[TRAIN_SPLIT:], labels[TRAIN_SPLIT:]

    detector = HybridDetector()
    detector.fit(train_s, train_l)
    models = run_comparison(detector, detector.pta,
                            train_s, train_l, test_s, test_l)

    # ── Hybrid behaviour on the test set ─────────────────────────────────────
    outputs   = detector.evaluate_batch(test_s)
    decisions = [o["decision"] for o in outputs]
    cleared   = [o["stage"] == "PTA" for o in outputs]
    preds     = [0 if d == "ALLOW" else 1 for d in decisions]
    tn, fp, fn, tp = confusion_matrix(test_l, preds, labels=[0, 1]).ravel()

    # ── Latency, every model timed one session at a time ─────────────────────
    escalated = [s for s, c in zip(test_s, cleared) if not c]
    mlp = DeepLearningModel()
    mlp.fit(None, train_s, train_l)
    latency = {
        "stage1_only_ms":    _ms_per_session(detector._stage1_pta_score, test_s),
        "hybrid_full_ms":    _ms_per_session(detector.evaluate_session, test_s),
        "stage2_only_ms":    _ms_per_session(detector._stage2_ml_risk, escalated)
                             if escalated else None,
        "mlp_single_ms":     _ms_per_session(lambda s: mlp.predict([s]), test_s),
        "mlp_batched_ms":    next(m["ms/sess"] for m in models
                                  if m["Model"].startswith("Deep")),
    }

    scores = [detector._stage1_pta_score(s) for s in test_s]
    with open(os.path.join(OUT, f"tree_rules_{name}.txt"), "w",
              encoding="utf-8") as f:
        f.write(detector.explain())

    return {
        "models": models,
        "hybrid": {
            "confusion_matrix": {"tn": int(tn), "fp": int(fp),
                                 "fn": int(fn), "tp": int(tp)},
            "pta_threshold":     round(detector.pta_threshold, 4),
            "stage1_cleared":    int(sum(cleared)),
            "stage1_cleared_pct": round(100 * sum(cleared) / len(test_s), 1),
            "attacks_cleared_at_stage1":
                int(sum(1 for c, y in zip(cleared, test_l) if c and y == 1)),
            "legit_cleared_pct_of_legit":
                round(100 * sum(1 for c, y in zip(cleared, test_l)
                                if c and y == 0) / test_l.count(0), 1),
            "decisions": {d: decisions.count(d)
                          for d in ("ALLOW", "CHALLENGE", "BLOCK")},
            "tree_depth":  int(detector.ml.model.get_depth()),
            "tree_leaves": int(detector.ml.model.get_n_leaves()),
        },
        "latency_ms": {k: (round(v, 4) if v is not None else None)
                       for k, v in latency.items()},
        "_scores": {"legit":  [s for s, y in zip(scores, test_l) if y == 0],
                    "attack": [s for s, y in zip(scores, test_l) if y == 1]},
    }


# ── Figures ──────────────────────────────────────────────────────────────────
def _grouped_bars(ax, results, metric, ylabel):
    names = [m["Model"] for m in results[DATASETS[0][0]]["models"]]
    x, w  = np.arange(len(names)), 0.38
    for i, (ds, _) in enumerate(DATASETS):
        vals = [m[metric] for m in results[ds]["models"]]
        bars = ax.bar(x + (i - 0.5) * w, vals, w, label=ds)
        ax.bar_label(bars, fmt="%.1f", fontsize=7, padding=1)
    ax.set_xticks(x, [SHORT_NAMES[n] for n in names], fontsize=8)
    ax.set_ylabel(ylabel)
    ax.legend(fontsize=8)


def figures(results):
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.2))
    _grouped_bars(axes[0], results, "Accuracy", "Accuracy (%)")
    axes[0].set_ylim(0, 105); axes[0].set_title("Detection accuracy")
    _grouped_bars(axes[1], results, "F1", "F1 score (%)")
    axes[1].set_ylim(0, 105); axes[1].set_title("F1 score")
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig1_accuracy_f1.png"), dpi=200)

    fig, axes = plt.subplots(1, 2, figsize=(12, 4.2))
    _grouped_bars(axes[0], results, "FPR %", "False positive rate (%)")
    axes[0].set_title("False positives (legitimate users flagged)")
    _grouped_bars(axes[1], results, "FNR %", "False negative rate (%)")
    axes[1].set_title("False negatives (attacks missed)")
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig2_error_rates.png"), dpi=200)

    fig, axes = plt.subplots(1, 2, figsize=(12, 4.2))
    for ax, (ds, _) in zip(axes, DATASETS):
        sc   = results[ds]["_scores"]
        bins = np.linspace(0, max(max(sc["legit"]), max(sc["attack"])), 60)
        ax.hist(sc["legit"],  bins=bins, alpha=0.7, density=True, label="Legitimate")
        ax.hist(sc["attack"], bins=bins, alpha=0.7, density=True, label="Attack")
        thr = results[ds]["hybrid"]["pta_threshold"]
        ax.axvline(thr, color="black", linestyle="--", label=f"learned θ = {thr:.3f}")
        ax.set_title(ds); ax.set_xlabel("PTA suspicion score"); ax.set_ylabel("Density")
        ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig3_pta_scores.png"), dpi=200)

    labels = ["Stage 1 only\n(cleared path)", "Hybrid\n(full)",
              "MLP\n(one session)", "MLP\n(batched)"]
    keys   = ["stage1_only_ms", "hybrid_full_ms", "mlp_single_ms", "mlp_batched_ms"]
    fig, ax = plt.subplots(figsize=(8, 4.2))
    x, w = np.arange(len(keys)), 0.38
    for i, (ds, _) in enumerate(DATASETS):
        vals = [results[ds]["latency_ms"][k] for k in keys]
        bars = ax.bar(x + (i - 0.5) * w, vals, w, label=ds)
        ax.bar_label(bars, fmt="%.3f", fontsize=7, padding=1)
    ax.set_xticks(x, labels, fontsize=8); ax.set_ylabel("ms per session")
    ax.set_title("Processing time per session"); ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig4_latency.png"), dpi=200)

    fig, axes = plt.subplots(1, 2, figsize=(12, 4.2))
    for ax, (ds, _) in zip(axes, DATASETS):
        h       = results[ds]["hybrid"]
        allow2  = h["decisions"]["ALLOW"] - h["stage1_cleared"]
        parts   = [("ALLOW at Stage 1", h["stage1_cleared"]),
                   ("ALLOW at Stage 2", allow2),
                   ("CHALLENGE", h["decisions"]["CHALLENGE"]),
                   ("BLOCK", h["decisions"]["BLOCK"])]
        bars = ax.bar([p[0] for p in parts], [p[1] for p in parts],
                      color=["#2e7d32", "#81c784", "#ef6c00", "#c62828"])
        total = sum(p[1] for p in parts)
        ax.bar_label(bars, labels=[f"{p[1]} ({100*p[1]/total:.1f}%)" for p in parts],
                     fontsize=8)
        ax.set_title(f"{ds}: decisions on {total} test sessions")
        ax.tick_params(axis="x", labelsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig5_decisions.png"), dpi=200)
    plt.close("all")


def seed_sweep(builder, seeds):
    """Mean ± std of each model's metrics over several dataset seeds."""
    runs = []
    for seed in seeds:
        sessions, labels = builder(n_sessions=N, seed=seed)
        detector = HybridDetector()
        detector.fit(sessions[:TRAIN_SPLIT], labels[:TRAIN_SPLIT])
        runs.append(run_comparison(detector, detector.pta,
                                   sessions[:TRAIN_SPLIT], labels[:TRAIN_SPLIT],
                                   sessions[TRAIN_SPLIT:], labels[TRAIN_SPLIT:]))
    out = {}
    for i, model in enumerate(runs[0]):
        out[model["Model"]] = {
            metric: {"mean": round(float(np.mean([r[i][metric] for r in runs])), 1),
                     "std":  round(float(np.std([r[i][metric] for r in runs])), 1)}
            for metric in ("Accuracy", "F1", "FPR %", "FNR %")}
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    results = {}
    for name, builder in DATASETS:
        print(f"Measuring {name}...")
        results[name] = measure(name, builder)
    figures(results)

    seeds = [42, 1, 2, 3, 4]
    for name, builder in DATASETS:
        print(f"Seed sweep {name} ({len(seeds)} seeds)...")
        results[name]["seed_sweep"] = {"seeds": seeds,
                                       "models": seed_sweep(builder, seeds)}

    summary = {ds: {k: v for k, v in r.items() if not k.startswith("_")}
               for ds, r in results.items()}
    with open(os.path.join(OUT, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps({ds: {"hybrid": s["hybrid"], "latency_ms": s["latency_ms"]}
                      for ds, s in summary.items()}, indent=2))
    print(f"\nWrote figures, tree rules and summary.json to {OUT}/")


if __name__ == "__main__":
    main()
