"""
redteam.py
==========
Adversarial evaluation of the hybrid detector (SDSC-HTTP style data).
Each experiment prints its findings; nothing here changes the detector.

  E1  Hand-crafted evasions
  E2  Attacker search: most checkout load per second that still gets ALLOW
  E3  Splitting the attack across sessions and IPs (traffic simulation)
  E4  Manipulating the first think time
  E5  Poisoning: attack sessions mislabelled as legitimate in the training logs
  E6  Distribution shift: site changes, unusual users, human-paced bots
  E7  Base rate: precision when attacks are rare
  E8  Page workload in the learned PTA
"""

import bisect
import random
import sys
import numpy as np

from hybrid_detector import HybridDetector
from pta.datasets import (build_sdsc_dataset, generate_sdsc_normal_session,
                          SDSC_PAGES, SDSC_FLOW, SDSC_WEIGHTS, SDSC_COST, _walk)
from pta.traffic import sessionize, LoadGuard, ClientBudget

sys.stdout.reconfigure(encoding="utf-8")

N, TRAIN_SPLIT = 10000, 8000
FUNNEL = ["index", "search", "product", "cart", "checkout"]
SEVERITY = {"ALLOW": 0, "CHALLENGE": 1, "BLOCK": 2}


def fit(train_s, train_l):
    d = HybridDetector()
    d.fit(train_s, train_l, page_cost=SDSC_COST)
    return d


def allowed(d, s):
    return d.evaluate_session(s)["decision"] == "ALLOW"


def checkout_load(s):
    """Checkout requests per second: the cost an asymmetric attacker wants."""
    dur = sum(t for _, t in s[1:]) or 1e-6   # first gap is before the session
    return sum(p == "checkout" for p, _ in s) / dur


def header(title):
    print(f"\n{'=' * 72}\n  {title}\n{'=' * 72}")


def e1_evasions(d):
    header("E1  Hand-crafted evasions")
    cases = [
        ("Checkout flood",                  [("checkout", 0.1)] * 6),
        ("Funnel x2 at 0.4 s (bot speed)",  [(p, 0.4) for p in FUNNEL] * 2),
        ("Funnel x2 at 0.1 s",              [(p, 0.1) for p in FUNNEL] * 2),
        ("Decoy page, then product x6 0.1 s", [("index", 1.0)] + [("product", 0.1)] * 6),
        ("Product x3 at 1.0 s",             [("index", 1.0)] + [("product", 1.0)] * 3),
        ("Product x4 at 1.0 s",             [("index", 1.0)] + [("product", 1.0)] * 4),
        ("Product x5 at 1.0 s",             [("index", 1.0)] + [("product", 1.0)] * 5),
        ("Unknown page 'admin' flood",      [("admin", 0.1)] * 6),
        ("Paced at 0.55 s, 7 requests",     [(p, 0.55) for p in
                                             ["index", "search", "product", "search",
                                              "product", "cart", "checkout"]]),
        ("Paced at 0.55 s, 14 requests",    [(p, 0.55) for p in
                                             ["index", "search", "product", "search",
                                              "product", "cart", "checkout"] * 2]),
    ]
    for name, s in cases:
        r = d.evaluate_session(s)
        p = "—" if r["attack_prob"] is None else f"{r['attack_prob'] * 100:.0f}%"
        print(f"  {name:36} {r['decision']:9} p={p:>5}")


def e2_attacker_search(d, test_s, test_l, iters=4000, seed=0):
    header("E2  Attacker search: maximise checkout/s while staying ALLOWED (≥5 requests)")
    rng = random.Random(seed)
    legit_loads = [checkout_load(s) for s, y in zip(test_s, test_l) if y == 0 and len(s) > 1]
    p99 = float(np.percentile(legit_loads, 99))

    def mutate(s):
        s = list(s)
        op = rng.random()
        i = rng.randrange(len(s))
        if op < 0.35:
            s[i] = (rng.choice(SDSC_PAGES), s[i][1])
        elif op < 0.7:
            s[i] = (s[i][0], round(max(0.05, s[i][1] * rng.uniform(0.5, 1.3)), 2))
        elif op < 0.85 and len(s) < 15:
            s.insert(i, (rng.choice(SDSC_PAGES), round(rng.uniform(0.1, 2.0), 2)))
        elif len(s) > 5:      # shorter sessions are E3's problem
            s.pop(i)
        return s

    best = [(p, 2.0) for p in FUNNEL]            # an ordinary, allowed shopper
    best_load = checkout_load(best)
    for _ in range(iters):
        cand = mutate(best)
        if allowed(d, cand) and checkout_load(cand) > best_load:
            best, best_load = cand, checkout_load(cand)
    print(f"  Legitimate users, 99th percentile : {p99:.2f} checkout/s")
    print(f"  Best ALLOWED attack found         : {best_load:.2f} checkout/s "
          f"({best_load / p99:.1f}x)")
    print(f"  Session: {best}")


# ── E3: traffic simulation ───────────────────────────────────────────────────
def _timeline(session, client, start):
    """Requests of a session as (client, timestamp, page)."""
    t, out = start, []
    for i, (page, think) in enumerate(session):
        if i:
            t += think
        out.append((client, round(t, 3), page))
    return out


def _decide(d, sessions, guard_times, guard_flags, budget_over):
    """Decision per server-side session, with the site load guard and the
    client budget applied at the session's last request."""
    out = []
    for client, start, s in sessions:
        end = start + sum(t for _, t in s[1:])
        k = bisect.bisect_right(guard_times, end) - 1
        under_load = k >= 0 and guard_flags[k]
        dec = d.evaluate_session(s, under_load=under_load)["decision"]
        if budget_over.get(client, float("inf")) <= end and dec == "ALLOW":
            dec = "CHALLENGE"
        out.append((client, s, dec))
    return out


def e3_splitting(d, train_s, train_l):
    header("E3  Splitting the attack across sessions and IPs (5-minute simulation)")
    random.seed(3); np.random.seed(3)
    T = 300.0

    legit = []                                    # 600 visitors, one IP each
    for i in range(600):
        legit += _timeline(generate_sdsc_normal_session(), f"u{i}", random.uniform(0, T))

    splitter, splitter_bursts = [], []            # one IP, 2-request bursts
    for k in range(int(T / 0.5)):
        burst = _timeline([("cart", 0.0), ("checkout", 0.05)], "a1", k * 0.5)
        splitter += burst
        splitter_bursts.append([("cart", 0.0), ("checkout", 0.05)])

    botnet = [(f"b{i}", round(random.uniform(100, 200), 3), "checkout")
              for i in range(3000)]               # 3,000 IPs, one request each

    guard  = LoadGuard.calibrate(legit, SDSC_COST)
    budget = ClientBudget.calibrate([s for s, y in zip(train_s, train_l) if y == 0],
                                    SDSC_COST)
    stream = sorted(legit + splitter + botnet, key=lambda r: r[1])
    times, flags, over = [], [], {}
    for client, t, page in stream:
        guard.record(t, page); budget.record(client, t, page)
        times.append(t); flags.append(guard.under_load())
        if budget.over_budget(client) and client not in over:
            over[client] = t

    decided = _decide(d, sessionize(stream), times, flags, over)

    def share(pred, who):
        rows = [(s, dec) for c, s, dec in decided if who(c)]
        reqs = sum(len(s) for s, _ in rows)
        return 100 * sum(len(s) for s, dec in rows if pred(dec)) / max(reqs, 1)

    # Before the fixes: the attacker chose session boundaries, no guard or budget
    before_split = np.mean([d.evaluate_session(b)["decision"] == "ALLOW"
                            for b in splitter_bursts]) * 100
    print(f"  Load guard limit: {guard.limit:.0f} cost/s (2× busiest normal window); "
          f"client budget: {budget.limit:.0f} cost per 10 min")
    print(f"  Single-IP splitter, 600 two-request bursts:")
    print(f"    sessions as the attacker sends them, no guard : "
          f"{before_split:.0f}% of bursts allowed")
    print(f"    sessionized by the server + guard + budget    : "
          f"{share(lambda x: x == 'ALLOW', lambda c: c == 'a1'):.0f}% of requests allowed")
    print(f"  Botnet, 3,000 IPs × 1 checkout request:")
    print(f"    allowed with the fixes                        : "
          f"{share(lambda x: x == 'ALLOW', lambda c: c.startswith('b')):.0f}% of requests")
    print(f"  Collateral: legitimate requests challenged or blocked: "
          f"{share(lambda x: x != 'ALLOW', lambda c: c.startswith('u')):.1f}% "
          f"(blocked: {share(lambda x: x == 'BLOCK', lambda c: c.startswith('u')):.1f}%)")


def e4_first_gap(d):
    header("E4  Manipulating the first think time")
    flood = [("checkout", 0.1)] * 6
    for first in (0.1, 5, 30, 300):
        s = [("index", first)] + flood
        r = d.evaluate_session(s)
        print(f"  first gap {first:>5} s, then 6 x checkout @0.1 s → {r['decision']}")


def e5_poisoning(sessions, labels, test_s, test_l):
    header("E5  Poisoning: attack sessions labelled legitimate in training")
    train_s, train_l = sessions[:TRAIN_SPLIT], list(labels[:TRAIN_SPLIT])
    attack_idx = [i for i, y in enumerate(train_l) if y == 1]
    rng = random.Random(1)
    for frac in (0.0, 0.05, 0.10, 0.25, 0.50):
        poisoned = list(train_l)
        for i in rng.sample(attack_idx, int(frac * len(attack_idx))):
            poisoned[i] = 0
        d = fit(train_s, poisoned)
        preds = [0 if d.evaluate_session(s)["decision"] == "ALLOW" else 1 for s in test_s]
        att = [p for p, y in zip(preds, test_l) if y == 1]
        leg = [p for p, y in zip(preds, test_l) if y == 0]
        print(f"  {frac * 100:>4.0f}% of training attacks mislabelled → "
              f"missed {100 * (1 - np.mean(att)):5.1f}% of attacks, "
              f"FPR {100 * np.mean(leg):.2f}%, θ={d.pta_threshold:.3f}")


def e6_shift(d, train_s, train_l):
    header("E6  Distribution shift: traffic unlike the training data")
    rng = random.Random(2); np.random.seed(2)

    def legit(think, n=500, flow=SDSC_FLOW):
        out = []
        for _ in range(n):
            pages = _walk(flow, SDSC_PAGES, SDSC_WEIGHTS, rng.randint(3, 8))
            out.append([(p, think()) for p in pages])
        return out

    def rate(sessions):
        return np.mean([not allowed(d, s) for s in sessions]) * 100

    human = lambda: round(max(0.1, np.random.lognormal(0.7, 0.8)), 2)
    print(f"  Legit, as trained (log-normal ~2 s)         flagged: {rate(legit(human)):5.1f}%")
    print(f"  Legit, all fast users (~0.6 s)             flagged: "
          f"{rate(legit(lambda: round(max(0.1, np.random.lognormal(-0.5, 0.4)), 2))):5.1f}%")
    print(f"  Legit, mobile/slow users (~6 s)            flagged: "
          f"{rate(legit(lambda: round(max(0.1, np.random.lognormal(1.8, 0.5)), 2))):5.1f}%")
    new_flow = {k: dict(v) for k, v in SDSC_FLOW.items()}
    new_flow["product"] = {"wishlist": 0.3, "cart": 0.3, "search": 0.4}
    new_flow["wishlist"] = {"product": 0.6, "cart": 0.4}
    changed = legit(human, flow=new_flow)
    print(f"  Legit, after site adds a 'wishlist' page   flagged: {rate(changed):5.1f}%")
    print(f"    drift monitor: unknown-page share {100 * d.pta.unknown_page_share(changed):.1f}% "
          f"(training traffic: {100 * d.pta.unknown_page_share(train_s[:2000]):.1f}%)")

    def bots(think, n=500):
        out = []
        for _ in range(n):
            pages = _walk(SDSC_FLOW, SDSC_PAGES, SDSC_WEIGHTS, rng.randint(6, 14),
                          avoid_logout=True)
            out.append([(p, think()) for p in pages])
        return out

    print(f"  Bots on real paths, 0.3–0.5 s              caught : "
          f"{rate(bots(lambda: round(rng.uniform(0.3, 0.5), 2))):5.1f}%")
    print(f"  Bots on real paths, 0.5–1.0 s              caught : "
          f"{rate(bots(lambda: round(rng.uniform(0.5, 1.0), 2))):5.1f}%")
    print(f"  Bots on real paths, human timing, 1 session caught : {rate(bots(human)):5.1f}%")

    # A human-paced bot only adds load by running far longer than a visitor
    budget = ClientBudget.calibrate([s for s, y in zip(train_s, train_l) if y == 0],
                                    SDSC_COST)
    pages = _walk(SDSC_FLOW, SDSC_PAGES, SDSC_WEIGHTS, 400, avoid_logout=True)
    t, flagged_at = 0.0, None
    for i, p in enumerate(pages):
        t += human() if i else 0.0
        budget.record("m1", t, p)
        if flagged_at is None and budget.over_budget("m1"):
            flagged_at = (i + 1, t)
    if flagged_at:
        print(f"  Same bot running continuously: over the client budget after "
              f"{flagged_at[0]} requests ({flagged_at[1]:.0f} s) → challenged")
    else:
        print("  Same bot running continuously: never exceeded the client budget")


def e7_base_rate(d, test_s, test_l):
    header("E7  Base rate: precision when attacks are rare")
    out = [d.evaluate_session(s)["decision"] for s in test_s]
    tpr = np.mean([o != "ALLOW" for o, y in zip(out, test_l) if y == 1])
    floor = 1 / test_l.count(0)                     # 0 observed ≠ 0 in reality
    for kind, pred in (("flagged (CHALLENGE or BLOCK)", lambda o: o != "ALLOW"),
                       ("blocked outright", lambda o: o == "BLOCK")):
        fpr = max(np.mean([pred(o) for o, y in zip(out, test_l) if y == 0]), floor)
        print(f"  Innocent users {kind}: {fpr * 100:.2f}% of legitimate sessions")
        for prevalence in (0.20, 0.01, 0.001):
            prec = tpr * prevalence / (tpr * prevalence + fpr * (1 - prevalence))
            print(f"    attacks = {prevalence * 100:>5.1f}% of sessions → "
                  f"{prec * 100:5.1f}% of {kind.split(' ')[0]} sessions are attacks")


def e8_workload(d):
    header("E8  Page workload in the learned PTA")
    w = d.pta.page_workload
    for page in sorted(w, key=w.get, reverse=True):
        print(f"  {page:9} W = {w[page]:.2f}")


def main():
    sessions, labels = build_sdsc_dataset(n_sessions=N)
    train_s, train_l = sessions[:TRAIN_SPLIT], labels[:TRAIN_SPLIT]
    test_s,  test_l  = sessions[TRAIN_SPLIT:], labels[TRAIN_SPLIT:]
    d = fit(train_s, train_l)
    e1_evasions(d)
    e2_attacker_search(d, test_s, test_l)
    e3_splitting(d, train_s, train_l)
    e4_first_gap(d)
    e5_poisoning(sessions, labels, test_s, test_l)
    e6_shift(d, train_s, train_l)
    e7_base_rate(d, test_s, test_l)
    e8_workload(d)


if __name__ == "__main__":
    main()
