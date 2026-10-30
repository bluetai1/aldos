# Red-team report: Hybrid PTA + Decision Tree detector

**Target:** the detector trained on 8,000 SDSC-HTTP style sessions (the one used by `main.py`
and `demo.py`).
**Reproduce:** `python redteam.py`. Experiments E1–E8 below map to the script's sections.

The red-team ran twice:
1. **Against the original detector**, which found the problems below.
2. **After the fixes**, which gave the "After" numbers below.

---

## Summary

| # | Finding | Severity | Before | After | Status |
|---|---------|----------|--------|-------|--------|
| 1 | Splitting the attack into tiny sessions | Critical | 100% of bursts allowed; 3,000-IP botnet allowed | 0% allowed (one IP); 1% allowed (botnet) | **Fixed** |
| 2 | Website changes make real users look like attackers | Critical | 26.8% of real users flagged | 0.2%, and the drift monitor fires | **Fixed** |
| 3 | Bots following real paths | High | 0.8% caught at 0.5–1.0 s | 51.8% per session; 98.0% at 0.3–0.5 s; continuous human-paced bot challenged after 21 requests | **Mitigated** |
| 4 | Page workload ignored | High | W = 1 everywhere | W learned per page; cost-per-second feature | **Fixed** |
| 5 | Base rate: innocent users blocked | Medium | Precision 61.5% at 0.1% prevalence | 60.3%; only 0.06% of real users blocked | **Measured; inherent** |
| 6 | Rules learned from one or two examples | Medium | 0.4 s funnel and 0.55 s pacing allowed | Funnel blocked; 0.55 s blocked at 14 requests | **Fixed** |
| 7 | Brittle, rarely used graded response | Medium | 3/4/5 repeats → ALLOW/CHALLENGE/BLOCK | 3/4 → ALLOW, 5 → BLOCK; CHALLENGE still rare | **Open** |
| 8 | Accuracy measured in-distribution only | Medium | Not measured | Leave-one-family-out and shift tests reported | **Measured** |
| 9 | Poisoning the training labels | Low | 5.8% missed at 50% poisoned | 18.5% missed at 50% poisoned | **Worse; documented** |
| 10 | Manipulating the first think time | Low | Blocked | Blocked | Held |
| 11 | Flooding unknown URLs | Low | Blocked | Blocked (needed a fix after #2) | Held |

---

## 1. Session splitting (Critical → Fixed)

**The attack:** the detector judged each session alone, and the attacker decided where sessions
began and ended.
- A single request has no transitions, so its PTA score was 0 and it was always cleared.
- A 2-request `cart → checkout` burst at 0.05 s was allowed, at 18× the checkout rate of the
  heaviest 1% of real users.
- Repeated from one IP, or spread across thousands, none of these bursts was ever linked.

**The fix** (`pta/traffic.py`, `hybrid_detector.py`):
- **`sessionize()`:** the server forms sessions per client, ending them after 5 minutes of
  inactivity or a logout. An attacker can no longer choose session boundaries.
- **Sessions shorter than 3 requests** are not judged alone. They are allowed normally, but
  challenged when the site is under unusual load.
- **`LoadGuard`:** a site-wide meter of server cost per second. Its limit is 2× the busiest
  normal 10-second window.
- **`ClientBudget`:** each client's server cost over 10 minutes, across sessions. Its limit is 2×
  the costliest real visitor session.

**After** (E3, a 5-minute simulation with 600 real visitors):

| Attacker | Before | After |
|---|---|---|
| One IP sending 600 two-request bursts | 100% of bursts allowed | **0%** of its requests allowed |
| 3,000 IPs, one checkout request each | all allowed | **1%** allowed |
| Collateral to real users | — | 1.3% of real requests challenged, 0.2% blocked |

**Remaining risk:** a botnet of human-paced, multi-request sessions looks like a flash crowd. The
load guard challenges only short sessions. Cross-session reputation (cookies, device
fingerprints, IP reputation) would be the next layer.

## 2. Website changes (Critical → Fixed)

**The attack:** adding one page (`wishlist`) to the site without retraining flagged **26.8% of
real users**. Unknown transitions scored the maximum, and the tree's strongest rule is "the
session contains a transition real users never make".

**The fix:**
- Steps involving a page the PTA has never seen are **skipped**. An unseen transition between
  two *known* pages still scores the maximum.
- Stage 1 only fast-paths a session if it could score at least two transitions, so a flood of
  unknown URLs can't slip through as "clean".
- `PTAModel.unknown_page_share()` reports the share of requests to unknown pages. This is the
  signal to retrain.

**After (E6):** 0.2% of real users flagged after the site change. The drift monitor reports
5.3% unknown pages, against 0.0% in the training traffic. A flood of unknown `admin` URLs is
still blocked.

## 3. Bots following real paths (High → Mitigated)

**The attack:** bots that follow the legitimate navigation flow. At 0.5–1.0 s per click, only
0.8% were caught. Both signals look normal: the path is real, and the timing overlaps fast
humans.

**The fix:**
- **A new attack type, A6** (path-following bots at 0.05–1.0 s, 4–14 requests), added to the
  training data.
- **Timing-regularity features:** `think_time_cv` and `median_think_time`. Bots keep steady
  timing; humans vary.
- **`ClientBudget`** for bots that keep going.

**After (E6):**

| Bot pacing on real paths | Caught |
|---|---|
| 0.3–0.5 s | 98.0% |
| 0.5–1.0 s | 51.8% per session |
| Human-like, one session | 0% |
| Human-like, running continuously | challenged by the client budget after 21 requests (64 s) |

**Attacker search (E2):** the best allowed single session reaches 3.0× a heavy user's checkout
rate. Sessionization stops the attacker repeating it from the same IP.

**Remaining risk:** per session, this is the floor for any behavioural detector. An attacker who
behaves exactly like a human costs exactly what a human costs. The defence against them at scale
is volume-based (budget, load guard).

**Generalisation caveat:** if A6 is left out of training entirely, the detector catches only
2.7–34.5% of A6 sessions (see `report.py`, leave-one-family-out). It only recognises these bots
because it was trained on them.

## 4. Workload (High → Fixed)

**The attack:** every edge in the learned PTA had W = 1, so `checkout` counted the same as
`index`. That contradicts the premise of an asymmetric attack, which is defined by targeting
expensive pages.

**The fix:**
- `PTAModel.learn(page_cost=...)` sets W to each page's server cost relative to an average
  request. Learned values: checkout 3.18, cart 1.59, search 1.19, product 0.80, login 0.80,
  profile 0.60, index 0.40, logout 0.20.
- A `cost_rate` feature (server cost per second) feeds the tree.
- The client budget and load guard also work in cost, not request counts.

**Caveat:** the page costs in `datasets.py` are assumptions. In deployment, they should be
learned from response-time logs.

## 5. Base rate (Medium → Measured; inherent)

**The problem:** the benchmark has 20% attacks; real traffic has far fewer, so false positives
dominate.

**What changed:** `report.py` and E7 now report precision at 20%, 1% and 0.1% prevalence,
separately for "flagged" (CHALLENGE or BLOCK) and "blocked".

**After (SDSC, seed 42):** 0.06% of real users were blocked, which is 1 user in 1,563 and is
also the measurement floor.

| Attacks as a share of sessions | Precision of BLOCK |
|---|---|
| 20% | 99.7% |
| 1%  | 93.9% |
| 0.1% | 60.3% |

On ClarkNet, BLOCK precision at 0.1% prevalence is 33.8%.

**Why it isn't "fixed":** at very low prevalence, any detector with a non-zero false-positive
rate mostly flags innocent users. The mitigations are policy:
- Send low-confidence flags to CHALLENGE, not BLOCK.
- Measure on real traffic to get a real false-positive rate.
- Tune thresholds for the cost of each error, not for accuracy.

## 6. Rules learned from one or two examples (Medium → Fixed)

**The attack:**
- The shopping funnel twice at 0.4 s was allowed, by a tree leaf learned from a single session.
- 7 requests paced at 0.55 s (just above the 0.5 s "rapid" cut-off) were allowed.

**The fix:**
- The tree's depth and minimum leaf size (10–40 sessions) are chosen by cross-validation on the
  training data. No leaf can rest on one or two examples.
- Continuous timing features reduce the reliance on the 0.5 s cut-off.

**After (E1):**

| Session | Decision |
|---|---|
| Funnel ×2 at 0.4 s | BLOCK |
| 0.55 s pacing, 7 requests | still ALLOW (2%) |
| 0.55 s pacing, 14 requests | BLOCK |

A short, regular bot at 0.55 s gets through one session; continuing gets it blocked, or caught
by the client budget.

## 7. Graded response (Medium → Open)

**The problem:** CHALLENGE fired for 0 of 2,000 SDSC test sessions and 12 of 2,000 ClarkNet
sessions. Most tree leaves are nearly pure, so attack probabilities are almost always near 0% or
100%.

In E1, a session repeating one page at about 1 s now goes:

| Repeats | Decision | Attack probability |
|---|---|---|
| 3 | ALLOW | 28% |
| 4 | ALLOW | 28% |
| 5 | BLOCK | 100% |

**Why it's still open:** the synthetic data has few genuinely ambiguous sessions. Proper
calibration (e.g. `CalibratedClassifierCV`, or a small calibrated ensemble with rules extracted
for explanation) needs real traffic to tune against. Adding it here would mean tuning to a
generator.

## 8. In-distribution evaluation (Medium → Measured)

**What changed:** `report.py` now reports two extra evaluations.

**Leave-one-family-out:** train without one attack family, then test on that family.

| Family left out | SDSC | ClarkNet |
|---|---|---|
| A2 | 82.4% | 97.1% |
| A6 | **34.5%** | **2.7%** |
| Others | 93.8–100% | 95.4–100% |

**Distribution shift (E6):** real users who are all fast (~0.6 s) are flagged 1.2% of the time;
slow mobile users 0.2%; users of a changed site 0.2%.

**Takeaway:** the detector generalises to new variants of attacks it has seen, but not to a new
*kind* of attack. Real logs are the only real test.

## 9. Poisoning (Low → Worse; documented)

**The attack:** mislabel a share of the training attacks as legitimate (E5). This simulates
attack traffic hidden in "clean" logs.

| Training attacks mislabelled | Attacks missed | FPR  |
|---|---|---|
| 0%  | 2.7%  | 0.06% |
| 10% | 3.2%  | 0.58% |
| 25% | 5.7%  | 0.51% |
| 50% | 18.5% | 0.58% |

**Why it got worse:** the more flexible, cross-validated tree also fits poisoned labels more
closely.

**Mitigation:** learn the PTA and labels from verified-clean traffic (e.g. customers who
completed purchases), and watch θ and the per-family detection rates for drift.

## 10–11. First think time and unknown URLs (Held)

**First think time:** pausing between 0.1 s and 300 s before a flood is still blocked. The streak
features don't depend on the first gap.

**Unknown URLs:** a flood of an unknown `admin` page is still blocked. Fix #2 at first let it
through, because a session with no scorable transitions had a PTA score of 0. Stage 1 now
fast-paths only sessions it could actually score.
