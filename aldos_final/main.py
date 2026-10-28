from hybrid_detector import HybridDetector
from pta.simulate_data import (generate_normal_session,
                                generate_attack_session,
                                generate_borderline_session,
                                generate_noisy_normal_session,
                                generate_noisy_attack_session)
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

    detector = HybridDetector()
    detector.train(n_samples=200)

    # ── Individual session tests ───────────────────────────────
    test_cases = [
        ("Normal user",            generate_normal_session()),
        ("DDoS attacker",          generate_attack_session()),
        ("Borderline / slow bot",  generate_borderline_session()),
        ("Fast legitimate user",   [("login",0.6),("dashboard",0.8),("logout",0.5)]),
        ("Medium-risk bot",        [("search",0.3),("search",0.4),("dashboard",0.3),
                                    ("search",0.2),("logout",0.8)]),
        ("Noisy normal",           generate_noisy_normal_session()),
        ("Noisy attack",           generate_noisy_attack_session()),
        ("Hand-crafted attack",    [("login",0.08),("login",0.09),
                                    ("search",0.07),("search",0.08)]),
    ]

    print(f"\nEvaluating {len(test_cases)} sessions...\n")
    for label, session in test_cases:
        result = detector.evaluate_session(session)
        print_result(label, session, result)

    # ── Batch ─────────────────────────────────────────────────
    print(f"\n\n{'='*60}")
    print("  Batch evaluation (10 random sessions)")
    print("=" * 60)
    mixed = ([generate_normal_session()       for _ in range(3)] +
             [generate_noisy_normal_session() for _ in range(2)] +
             [generate_attack_session()       for _ in range(2)] +
             [generate_noisy_attack_session() for _ in range(2)] +
             [generate_borderline_session()   for _ in range(1)])
    random.shuffle(mixed)
    results   = detector.evaluate_batch(mixed)
    decisions = [r["decision"] for r in results]
    print(f"\n  {'#':<6} {'PTA Score':<12} {'Stage':<6} {'Decision':<12} {'Attack Prob'}")
    print(f"  {'─'*55}")
    for i, (sess, res) in enumerate(zip(mixed, results)):
        ap     = res['attack_prob']
        ap_str = f"{ap*100:.1f}%" if ap is not None else "N/A"
        print(f"  {i+1:<6} {res['pta_score']:<12} {res['stage']:<6} {res['decision']:<12} {ap_str}")
    print(f"\n  ALLOW    : {decisions.count('ALLOW')}")
    print(f"  CHALLENGE: {decisions.count('CHALLENGE')}")
    print(f"  BLOCK    : {decisions.count('BLOCK')}")

    # ── Model Comparison: SDSC-HTTP (10,000 sessions) ─────────
    print(f"\n\n{'='*60}")
    print("  MODEL COMPARISON — SDSC-HTTP Dataset")
    print("  10,000 sessions | 8,000 train | 2,000 test")
    print(f"  (Reconstructed from Praseed & Thilagam 2021)")
    print("=" * 60)

    N = 10000
    TRAIN_SPLIT = 8000

    print("\n  Building SDSC-HTTP dataset...")
    sdsc_sessions, sdsc_labels = build_sdsc_dataset(n_sessions=N)
    train_s = sdsc_sessions[:TRAIN_SPLIT]; train_l = sdsc_labels[:TRAIN_SPLIT]
    test_s  = sdsc_sessions[TRAIN_SPLIT:]; test_l  = sdsc_labels[TRAIN_SPLIT:]

    detector_sdsc = HybridDetector()
    detector_sdsc.fit(train_s, train_l)

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
