"""
demo.py
=======
Interactive demo: a detector fitted on the SDSC-HTTP style dataset, ready
for testing sessions live.

    python -i demo.py

Then, at the >>> prompt:

    check([("index", 2.1), ("search", 3.4), ("product", 5.2)])
    check([("checkout", 0.1)] * 6)
    print(detector.explain())

Pages: index, login, search, product, cart, checkout, profile, logout.
Each step is (page, seconds since the previous request).
"""

import sys
from hybrid_detector import HybridDetector
from pta.datasets import build_sdsc_dataset, SDSC_PAGES

# θ and → below crash on consoles that aren't UTF-8 (e.g. Windows cp1252)
sys.stdout.reconfigure(encoding="utf-8")

print("Fitting detector on 8,000 SDSC-HTTP style sessions...")
sessions, labels = build_sdsc_dataset(n_sessions=10000)
detector = HybridDetector()
detector.fit(sessions[:8000], labels[:8000])
print(f"Ready. Learned Stage 1 threshold θ = {detector.pta_threshold:.3f}")
print(f"Pages: {', '.join(SDSC_PAGES)}\n")


def check(session):
    """Evaluate one session and print how the decision was reached."""
    r = detector.evaluate_session(session)
    print(f"  Session    : {' → '.join(p for p, _ in session)}")
    print(f"  Think times: {[t for _, t in session]}")
    print(f"  PTA score  : {r['pta_score']}  (θ = {detector.pta_threshold:.3f})")
    if r["stage"] == "PTA":
        print("  Stage 1    : below θ, cleared without the classifier")
    else:
        print(f"  Stage 2    : attack probability {r['attack_prob'] * 100:.1f}%")
    print(f"  Decision   : {r['decision']} ({r['risk']} risk)\n")


if __name__ == "__main__":
    examples = {
        "Shopper":           [("index", 2.1), ("search", 3.4), ("product", 5.2),
                              ("cart", 2.8), ("checkout", 4.0), ("logout", 1.5)],
        "Fast shopper":      [("index", 0.7), ("search", 1.1), ("product", 0.9),
                              ("cart", 0.8), ("checkout", 1.2)],
        "Checkout flood":    [("checkout", 0.1)] * 6,
        "Slow checkout bot": [("checkout", 1.8), ("checkout", 1.7), ("checkout", 1.9),
                              ("checkout", 1.8), ("checkout", 1.7)],
        "Random-page bot":   [("profile", 1.6), ("cart", 1.8), ("login", 1.7),
                              ("checkout", 1.6), ("index", 1.7)],
    }
    for name, s in examples.items():
        print(f"[{name}]")
        check(s)
    print("Try your own: check([(\"index\", 2.0), (\"product\", 0.1), ...])")
