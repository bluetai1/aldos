from hybrid_detector import HybridDetector
from pta.datasets import build_sdsc_dataset, build_clarknet_dataset
from pta.models_comparison import run_comparison, print_comparison_table
import random
import sys

# Box-drawing characters below crash on consoles that aren't UTF-8 (e.g. Windows cp1252)
sys.stdout.reconfigure(encoding="utf-8")

def print_result(label, session, result):
    attack     = result['attack_prob']
    attack_str = f"{attack * 100:.1f}%" if attack is not None else "N/A (cleared at Stage 1)"
    print(f"\n{'─'*60}")
    print(f"  [{label}]")
    print(f"  Session     : {session}")
    print(f"  PTA Score   : {result['pta_score']}")
    print(f"  Stage used  : {result['stage']}")
    print(f"  Decision    : {result['decision']}")
    print(f"  Risk level  : {result['risk']}")
    print(f"  Attack prob : {attack_str}")

def main():
    print("=" * 60)
    print("  AL-DDoS Hybrid Detection System")
    print("  PTA + Decision Tree — Two-Stage Pipeline")
    print("=" * 60)

    N = 10000
    TRAIN_SPLIT = 8000

    sdsc_sessions, sdsc_labels = build_sdsc_dataset(n_sessions=N)
    train_s = sdsc_sessions[:TRAIN_SPLIT]; train_l = sdsc_labels[:TRAIN_SPLIT]
    test_s  = sdsc_sessions[TRAIN_SPLIT:]; test_l  = sdsc_labels[TRAIN_SPLIT:]

    detector_sdsc = HybridDetector()
    detector_sdsc.fit(train_s, train_l)
    print(f"\n[TRAIN] Fitted on {TRAIN_SPLIT:,} SDSC-HTTP sessions "
          f"({train_l.count(0):,} legitimate, {train_l.count(1):,} attack). "
          f"Learned θ = {detector_sdsc.pta_threshold:.3f}")

    # ── Individual session tests ───────────────────────────────
    test_cases = [
        ("Normal shopper",       [("index",2.1),("search",3.4),("product",5.2),
                                  ("cart",2.8),("checkout",4.0),("logout",1.5)]),
        ("Checkout flood",       [("checkout",0.1)] * 6),
        ("Slow checkout bot",    [("checkout",1.8),("checkout",1.7),("checkout",1.9),
                                  ("checkout",1.8),("checkout",1.7)]),
        ("Fast legitimate user", [("index",0.7),("search",1.1),("product",0.9),
                                  ("cart",0.8),("checkout",1.2)]),
        ("Medium-risk bot",      [("search",0.3),("search",0.4),("product",0.3),
                                  ("search",0.2),("logout",0.8)]),
        ("Product browser",      [("index",2.0),("product",3.0),("product",2.5),
                                  ("product",4.1),("search",2.2)]),
        ("Disguised flood",      [("index",2.0),("search",2.5),("product",3.0)]
                                 + [("product",0.1)] * 6),
        ("Hand-crafted attack",  [("login",0.08),("login",0.09),
                                  ("search",0.07),("search",0.08)]),
    ]

    print(f"\nEvaluating {len(test_cases)} sessions...\n")
    for label, session in test_cases:
        result = detector_sdsc.evaluate_session(session)
        print_result(label, session, result)

    # ── Batch: held-out test sessions ──────────────────────────
    # 6 at random, plus examples of the Stage 1 fast path and of CHALLENGE
    outputs   = detector_sdsc.evaluate_batch(test_s)
    rng       = random.Random(7)
    cleared   = [i for i, o in enumerate(outputs) if o["stage"] == "PTA"][:2]
    challenge = [i for i, o in enumerate(outputs) if o["decision"] == "CHALLENGE"][:2]
    others    = [i for i in range(len(test_s)) if i not in cleared + challenge]
    picked    = cleared + challenge + rng.sample(others, 10 - len(cleared) - len(challenge))
    rng.shuffle(picked)

    print(f"\n\n{'='*60}")
    print("  Batch: 10 held-out test sessions")
    print("  (6 random + Stage 1 and CHALLENGE examples)")
    print("=" * 60)
    print(f"\n  {'#':<4} {'Truth':<8} {'PTA Score':<11} {'Stage':<6} {'Decision':<11} {'Attack Prob'}")
    print(f"  {'─'*55}")
    for n, i in enumerate(picked, 1):
        res    = outputs[i]
        truth  = "attack" if test_l[i] else "legit"
        ap     = res['attack_prob']
        ap_str = f"{ap*100:.1f}%" if ap is not None else "N/A"
        print(f"  {n:<4} {truth:<8} {res['pta_score']:<11} {res['stage']:<6} {res['decision']:<11} {ap_str}")
    decisions = [o["decision"] for o in outputs]
    print(f"\n  All {len(test_s):,} test sessions → ALLOW {decisions.count('ALLOW')}, "
          f"CHALLENGE {decisions.count('CHALLENGE')}, BLOCK {decisions.count('BLOCK')}")

    # ── Model Comparison: SDSC-HTTP (10,000 sessions) ─────────
    print(f"\n\n{'='*60}")
    print("  MODEL COMPARISON — SDSC-HTTP Dataset")
    print("  10,000 sessions | 8,000 train | 2,000 test")
    print(f"  (Reconstructed from Praseed & Thilagam 2021)")
    print("=" * 60)

    print("  Running all models...\n")
    sdsc_results = run_comparison(detector_sdsc, detector_sdsc.pta,
                                  train_s, train_l, test_s, test_l)
    print_comparison_table(sdsc_results, "SDSC-HTTP (10,000 sessions)")

    # ── Model Comparison: CLARKNET-HTTP (10,000 sessions) ─────
    print(f"\n{'='*60}")
    print("  MODEL COMPARISON — CLARKNET-HTTP Dataset")
    print("  10,000 sessions | 8,000 train | 2,000 test")
    print(f"  (Reconstructed from Praseed & Thilagam 2021)")
    print("=" * 60)

    print("\n  Building CLARKNET-HTTP dataset...")
    clark_sessions, clark_labels = build_clarknet_dataset(n_sessions=N)
    train_s = clark_sessions[:TRAIN_SPLIT]; train_l = clark_labels[:TRAIN_SPLIT]
    test_s  = clark_sessions[TRAIN_SPLIT:]; test_l  = clark_labels[TRAIN_SPLIT:]

    detector_clark = HybridDetector()
    detector_clark.fit(train_s, train_l)

    print("  Running all models...\n")
    clark_results = run_comparison(detector_clark, detector_clark.pta,
                                   train_s, train_l, test_s, test_l)
    print_comparison_table(clark_results, "CLARKNET-HTTP (10,000 sessions)")

    # ── Final summary ──────────────────────────────────────────
    print(f"\n{'='*60}")
    print("  FINAL SUMMARY")
    print("=" * 60)
    for res_list, ds in [(sdsc_results, "SDSC-HTTP"),
                          (clark_results, "CLARKNET-HTTP")]:
        ours = next(r for r in res_list if "Ours"    in r["Model"])
        pta  = next(r for r in res_list if "Praseed" in r["Model"])
        rw   = next(r for r in res_list if "Xu"      in r["Model"])
        dl   = next(r for r in res_list if "Neural"  in r["Model"])
        print(f"\n  [{ds}]")
        print(f"  {'Model':<30} {'Accuracy':>10} {'F1':>8} {'FPR %':>8}")
        print(f"  {'─'*58}")
        for label, r in [("► Ours (Hybrid PTA+DT)", ours),
                          ("  PTA Only",              pta),
                          ("  Random Walk",            rw),
                          ("  Deep Learning (MLP)",    dl)]:
            print(f"  {label:<30} {r['Accuracy']:>9}% {r['F1']:>7}% {r['FPR %']:>7}%")
    print()

if __name__ == "__main__":
    main()
