# Hybrid PTA + Decision Tree for Application-Layer DDoS Detection

A detector for **asymmetric application-layer DDoS attacks**: bots that take a web server down
with a small number of valid-looking requests to its most expensive pages.

- **Stage 1** is a **Probabilistic Timed Automaton (PTA)**, the model from Praseed & Thilagam
  (IEEE TIFS, 2021). It scores how normal a session's page order and timing are.
- **Stage 2** is a **Decision Tree** that gives each suspicious session an attack probability.
- **Graded response:** that probability maps to **Allow / Challenge (CAPTCHA) / Block** instead
  of the original system's binary block-or-allow.
- **Traffic layer:** server-side sessions, a per-client cost budget and a site-wide load guard
  stop attackers from splitting an attack across many sessions or IPs.

**Authors:** Tamirah Goode, Keila Chavez, Taiwo Ojo. CSIT 540 (Computer Networks Security),
Montclair State University.
**Paper:** *A Hybrid PTA and Decision Tree Framework for Application Layer DDoS Detection with
Graded Response* ([`Final_Research_Paper.docx.pdf`](Final_Research_Paper.docx.pdf)).

> **Note on results:** the paper reports 100% accuracy for the first version of this code. We
> later found that benchmark was flawed, red-teamed the detector, and fixed what we found. This
> README reports the current results. See [How the project evolved](#how-the-project-evolved).

---

## The problem

A firewall inspects individual requests, but in this attack every request is valid. A bot that
calls `/checkout` again and again sends nothing malformed. The only signal is **behaviour**:
- which pages are visited, and in what order;
- how long the client waits between clicks;
- how expensive those pages are to serve;
- how much a client consumes over time.

Praseed & Thilagam's PTA learns that behaviour from server logs, but its decision is binary. A
fast human who crosses the threshold gets blocked, and a careful bot that stays just under it
gets through. This project adds a second, explainable stage, a middle "challenge" option, and
the traffic-level defences that a session-by-session model can't provide on its own.

---

## Architecture

```
  raw requests (client, time, page)
            │
  ┌─────────▼───────────────────────────────┐   pta/traffic.py
  │ Server-side sessionization              │   (clients can't choose
  │ per client, 5-min inactivity or logout  │    session boundaries)
  └─────────┬───────────────────────────────┘
            │ session = [(page, think_time), ...]
            │
            ├── < 3 requests ──► too short to judge alone:
            │                    ALLOW, or CHALLENGE when the site-wide LoadGuard
            │                    reports unusual load
            ▼
  ┌──────────────────────────────────────────┐
  │ Stage 1: PTA suspicion score             │
  │ mean over transitions of                 │
  │ W · (1 − P_trans · P_think)              │
  └─────────┬────────────────────────────────┘
   score < θ│and ≥2 transitions scored     otherwise
       ┌────┴───────────────────────────────────┐
       ▼                                        ▼
     ALLOW              ┌───────────────────────────────────┐
                Stage 2 │ Decision Tree → attack probability │
                        └───────────────┬───────────────────┘
                          < 35%       35–70%       ≥ 70%
                          ALLOW     CHALLENGE      BLOCK

  ClientBudget: a client whose server cost over 10 minutes exceeds 2× the costliest
  real visitor session is challenged, even if every session looks human.
```

### Stage 1: PTA

The PTA is a directed graph learned from **legitimate** sessions. For each transition
`page i → page j` it stores:

| Parameter | Meaning |
|-----------|---------|
| `P_trans` | Transition probability, `n_ij / Σ_k n_ik` |
| `μ`, `σ`  | Think-time mean and spread |
| `W`       | Workload: the destination page's server cost relative to an average request. `checkout` is 3.2, `index` 0.4 |

Each step of a session is scored:

```
P_think   = exp(−|t − μ| / σ)
suspicion = W · (1 − P_trans · P_think)       # unseen transition → W
```

Steps involving a page that never appeared in training are **skipped, not penalised**. A new
page usually means the site changed, not that an attack is under way. A drift monitor
(`PTAModel.unknown_page_share`) reports when this is happening, so you know to retrain.

θ is **learned**: it is set to the lowest score of any training attack, so Stage 1 never
fast-paths a session that looks more normal than every attack seen in training.

### Stage 2: Decision Tree

The tree's depth and minimum leaf size are chosen by **3-fold cross-validation on the training
data** (depth 4–7; at least 10–40 training sessions per leaf, so no rule rests on one or two
examples).

| Feature | Captures |
|---------|----------|
| `request_rate`, `session_duration` | How fast and how long |
| `think_time_variance`, `think_time_cv`, `median_think_time` | Timing: bots are regular, humans vary |
| `rapid_requests`, `longest_rapid_streak` | Requests under 0.5 s, and the longest run of them |
| `page_repetition`, `longest_same_page_streak` | Hammering one page |
| `cost_rate` | Server cost per second: the asymmetric-attack signal |
| `pta_score`, `min_transition_prob` | Stage 1's view: unusual paths and timing |

The **streak** features can't be diluted by opening with a few normal pages (see
[Red-teaming](#red-teaming)). We chose a Decision Tree over a neural network so that **every
decision can be traced to readable if/then rules** (`detector.explain()`).

### Graded response

| Attack probability | Decision    | Action                          |
|--------------------|-------------|---------------------------------|
| < 35%              | `ALLOW`     | Proceed                         |
| 35–70%             | `CHALLENGE` | CAPTCHA or temporary rate limit |
| ≥ 70%              | `BLOCK`     | Terminate the session           |

---

## Results

**Setup:** each dataset has 10,000 sessions (80% legitimate, 20% attack), split 8,000 for
training and 2,000 for testing. Every model is trained on the same split and gets the same
behavioural features. The PTA Only and Random Walk thresholds are tuned for F1 on the training
data.

All values below are percentages: **mean ± standard deviation over 5 random seeds**. Reproduce
them with `python report.py`.

| Model                        | SDSC Accuracy | SDSC F1 | SDSC FPR | SDSC FNR | ClarkNet Accuracy | ClarkNet F1 | ClarkNet FPR | ClarkNet FNR |
|------------------------------|---------------|---------|----------|----------|-------------------|-------------|--------------|--------------|
| **Hybrid PTA + DT (ours)**   | **99.2 ± 0.3** | **98.0 ± 0.7** | 0.37 ± 0.42 | **2.5 ± 1.6** | **99.2 ± 0.1** | **97.9 ± 0.3** | 0.62 ± 0.23 | **1.8 ± 1.0** |
| PTA Only (Praseed 2021)      | 85.5 ± 1.1 | 60.6 ± 0.8 | 6.82 ± 2.24 | 44.9 ± 4.2 | 63.4 ± 0.5 | 47.0 ± 1.7 | 40.82 ± 1.43 | 20.5 ± 3.3 |
| Random Walk (Xu et al. 2014) | 94.5 ± 0.3 | 84.3 ± 1.4 | **0.0 ± 0.0** | 27.0 ± 2.0 | 90.1 ± 0.4 | 67.9 ± 2.6 | **0.0 ± 0.0** | 48.5 ± 3.0 |
| Deep Learning (MLP 64-32-16) | 97.2 ± 0.5 | 92.8 ± 1.5 | 1.03 ± 0.26 | 9.9 ± 2.1 | 97.9 ± 0.2 | 94.6 ± 0.8 | 0.53 ± 0.20 | 8.3 ± 1.6 |
| Rate Threshold (1.8 req/s)   | 87.5 ± 0.4 | 58.1 ± 1.1 | 1.20 ± 0.34 | 57.1 ± 0.8 | 86.5 ± 0.7 | 55.1 ± 1.7 | 1.75 ± 0.33 | 59.4 ± 1.6 |

**Takeaways:**

- **The hybrid has the best accuracy, F1 and miss rate on both datasets.** It misses about 2% of
  attacks; the other models miss 8–59%.
- **Each signal alone misses an attack type.** Rate Threshold sees only timing, so it misses
  human-paced bots. Random Walk sees only page order, so it never raises a false alarm but misses
  bots on normal-looking paths. The PTA score alone barely separates ClarkNet traffic.
- **False alarms are low, and rarely end in a block.** The hybrid flags 0.4–0.6% of real users.
  On the seed-42 test sets, only 0.06% (SDSC) and 0.19% (ClarkNet) of real users were blocked
  outright.
- **The tree is readable** ([`results/tree_rules_*.txt`](results/)). Its first rule, "the session
  contains a transition real users almost never make", catches 1,098 of 1,563 SDSC training
  attacks.
- **Per-session cost**, timed one session at a time:

  | Path                             | ms per session |
  |----------------------------------|----------------|
  | Stage 1 fast path                | ~0.01          |
  | Full hybrid                      | 0.16–0.18      |
  | MLP, one session at a time       | ~0.29          |
  | MLP, batched (not possible live) | 0.07–0.08      |

**What the extra evaluations show** (seed 42, from `results/summary.json`):

| | SDSC | ClarkNet |
|---|---|---|
| Detection by attack family (A1–A5) | 93.8–100% | 97.3–100% |
| Path-following bots (A6) | 87.9% | 93.3% |
| **Leave-one-family-out:** A6 when never seen in training | **34.5%** | **2.7%** |
| Leave-one-family-out: other families | 82–100% | 95–100% |
| Precision of BLOCK if 1% of sessions are attacks | 93.9% | 83.7% |
| Precision of BLOCK if 0.1% of sessions are attacks | 60.3% | 33.8% |
| Stage 1 fast path (share of test sessions) | 0.4% | 0.0% |

- **The detector only catches path-following bots that it was trained on.** Without A6 examples,
  it catches 2.7–34.5% of them.
- **At realistic attack rates, many blocks hit real users.** That's why low-confidence flags
  should be challenges rather than blocks.
- **Stage 1 has almost no safe fast path left.** Bots on real paths score almost like real
  users, so the lowest training-attack score (θ) is very low. Stage 1's value is now the evidence
  it feeds Stage 2; at about 0.17 ms per session, running Stage 2 on everything is affordable.

---

## Red-teaming

`python redteam.py` attacks the detector in eight ways. [`docs/red_team.md`](docs/red_team.md)
records what each attack found before the fixes and the result after them. In summary:

| Attack | Before fixes | After fixes |
|---|---|---|
| Split into 2-request sessions from one IP | 100% allowed | **0% allowed** (server-side sessionization) |
| 3,000-IP botnet, one checkout request each | allowed | **1% allowed** (LoadGuard); 1.3% of real requests challenged, 0.2% blocked |
| Site adds a new page | 26.8% of real users flagged | **0.2%**, and the drift monitor reports 5.3% unknown pages |
| Decoy page, then flood | allowed | **blocked** (streak features) |
| Real-path bot, 0.3–0.5 s | 62.6% caught | **98.0%** |
| Real-path bot, 0.5–1.0 s | 0.8% caught | **51.8%** per session; the client budget catches it if it continues |
| Human-paced bot running continuously | never caught | **challenged after 21 requests** (client budget) |
| Best allowed single session (attacker search) | 2.8× a heavy user's checkout rate | 3.0×; sessionization stops repeating it |
| Workload | W = 1 everywhere | Learned per page (checkout 3.2 … logout 0.2) |
| 50% of training attacks mislabelled | 5.8% missed | 18.5% missed |

---

## How the project evolved

| | Paper (v1) | Now |
|---|---|---|
| PTA on SDSC/ClarkNet | Hand-written graph, so the benchmark sites' pages were unknown | Learned per dataset, with page workload |
| Stage 1 threshold θ | Fixed at 0.60 | Learned from training attacks |
| Baselines | Fixed thresholds | Tuned for F1 on the same training split |
| Attacks | All 0.05–0.20 s floods | Floods, slow and human-paced bots, decoy prefixes, path-following bots (A6) |
| Legitimate users | Random pages | Navigation flows, plus 20% fast power users |
| Stage 2 | 5 features, fixed tree | 12 features, tree size chosen by cross-validation |
| Scope | One session at a time | Plus sessionization, client budget and load guard |
| Headline | 100% accuracy, 0% FPR | 99.2% / 99.2% accuracy, 0.4% / 0.6% FPR (5-seed mean) |
| Evidence | Figures not generated by the code | `report.py` and `redteam.py` regenerate every number |

**Why the numbers changed:**
- **Timing alone separated the classes in v1.** Even a one-line rate threshold scored 100%.
- **The v1 baselines weren't a fair comparison.** They ran on a graph that didn't contain the
  benchmark sites' pages.
- **Red-teaming found real gaps:** session splitting, site changes and mimicry bots. Closing them
  meant adding harder attacks to the data, which lowers the headline accuracy but makes it mean
  something.

[`docs/paper_revisions.md`](docs/paper_revisions.md) lists every paper section affected, with
replacement text.

---

## Datasets

The original SDSC-HTTP and ClarkNet-HTTP logs aren't readily available, so
[`pta/datasets.py`](pta/datasets.py) reconstructs sessions in their style:

- **SDSC-HTTP:** e-commerce pages (`index`, `login`, `search`, `product`, `cart`, `checkout`,
  `profile`, `logout`).
- **ClarkNet-HTTP:** news-portal pages (`home`, `news`, `sports`, `tech`, `login`, `search`,
  `archive`, `logout`).

**Legitimate users** follow a Markov navigation flow. Their think times are log-normal (mean
≈ 2 s), and 20% are fast power users (median ≈ 1 s).

**Attacks** come in six types, in equal shares:

| Type | Attack |
|------|--------|
| A1   | Random flood |
| A2   | Single-URL flood |
| A3   | Random asymmetric (high-workload pages) |
| A4   | Single-URL asymmetric (`checkout`) |
| A5   | Botnet (repeated scripted sequence) |
| A6   | **Path-following bot:** follows real navigation with regular 0.05–1.0 s pacing |

A1–A5 sessions are paced as a flood (40%), a slow bot (30%) or a human-paced but regular bot
(30%). 30% of them open with 1–3 normal-looking pages (a decoy).

**Page costs** (`SDSC_COST`, `CLARK_COST`) are assumed relative server costs. In deployment,
they would be learned from response-time logs.

---

## Project structure

```
aldos_final/
├── main.py                  # Demo: 8 sessions, 10 held-out sessions, five-model comparison
├── demo.py                  # Interactive: test your own sessions (python -i demo.py)
├── report.py                # Every result, figure and evaluation → results/
├── redteam.py               # Adversarial experiments E1–E8
├── hybrid_detector.py       # HybridDetector: fit / evaluate_session / explain
├── Final_Research_Paper.docx.pdf  # The paper (v1 results; see docs/paper_revisions.md)
├── requirements.txt         # numpy, scikit-learn, networkx, matplotlib
├── results/                 # summary.json, fig1–fig5, tree_rules_*.txt
├── docs/
│   ├── paper_revisions.md   # Section-by-section corrections to the paper
│   └── red_team.md          # Red-team findings, fixes and remaining risks
└── pta/
    ├── pta_model.py         # PTAModel: learned graph, page workload, drift monitor
    ├── scoring.py           # P_think, suspicion, session score, min transition prob
    ├── train_model.py       # Behavioural features + CV-tuned DecisionTreeClassifier
    ├── traffic.py           # sessionize(), ClientBudget, LoadGuard
    ├── datasets.py          # SDSC / ClarkNet style generators, page costs
    ├── simulate_data.py     # Small toy set used by detector.train()
    └── models_comparison.py # Baselines, threshold tuning, metrics, comparison table
```

---

## Running it

Requires Python 3.8+.

```bash
cd aldos_final
pip install -r requirements.txt
python main.py          # ~10 s. On Windows, use "py main.py" if python isn't on PATH
python -i demo.py       # interactive: check([("checkout", 0.1)] * 6)
python redteam.py       # ~1 min
python report.py        # a few minutes: seeds, leave-one-family-out, figures
```

### Using the detector

```python
from hybrid_detector import HybridDetector
from pta.datasets import SDSC_COST

detector = HybridDetector()
detector.fit(train_sessions, train_labels, page_cost=SDSC_COST)   # 0 = legit, 1 = attack

detector.evaluate_session([("checkout", 0.1)] * 6)
# {'pta_score': 3.18, 'stage': 'ML', 'decision': 'BLOCK', 'risk': 'HIGH', 'attack_prob': 1.0}
print(detector.explain())                                         # the tree as rules
```

For a live request stream, see `pta/traffic.py`:
- `sessionize()` turns raw `(client, time, page)` requests into sessions.
- `ClientBudget` and `LoadGuard` track per-client and site-wide cost.
- Pass `under_load=guard.under_load()` to `evaluate_session`.

`redteam.py` (E3) shows all three working together.

---

## Limitations

- **The data is synthetic.** Every result depends on the generators in `datasets.py`, including
  the assumed page costs. Validating on real logs is the most important next step.
- **Unseen attack families generalise poorly.** Path-following bots are caught only when
  training includes them (2.7–34.5% when it doesn't).
- **Human-paced bots can't be caught within a single session.** They are caught only by the
  client budget, after about a minute. A large enough botnet of them looks like a flash crowd:
  the load guard challenges short sessions, but not long human-looking ones.
- **`CHALLENGE` is rare** (0 and 12 of 2,000 test sessions). Most tree leaves are nearly pure,
  so the graded response is rarely exercised. Probability calibration is future work.
- **Precision collapses at realistic prevalence.** If 0.1% of sessions are attacks, only 34–60%
  of blocks hit attackers. The 0.06–0.19% innocent-block rate rests on only 1–3 real users in
  each test set, so it's an estimate with wide error bars.
- **The traffic-layer defences have their own costs.** The client budget and load guard are
  calibrated at 2× normal peaks. A heavy real user with several sessions in 10 minutes can
  exceed the budget and be challenged.
- **Poisoning weakens the detector at scale.** With 50% of training attacks mislabelled, it
  misses 18.5% of attacks. Build the PTA from verified-clean traffic.
- **The timings are rough.** They come from single-threaded Python on one laptop.

## Future work

- Evaluate on real logs, with response times for page costs.
- Calibrate probabilities so `CHALLENGE` reflects genuine uncertainty.
- Generate adversarial attacks automatically, and retrain on what gets through.
- Push `BLOCK` decisions to an SDN controller.
- Model HTTP/2 multiplexed sessions (Praseed & Thilagam, TIFS 2020).

## References

1. A. Praseed and P. S. Thilagam, "Modelling Behavioural Dynamics for Asymmetric Application Layer
   DDoS Detection," *IEEE Trans. Inf. Forensics Security*, vol. 16, pp. 617–626, 2021.
2. C. Xu, G. Zhao, G. Xie, and S. Yu, "Detection on Application Layer DDoS Using Random Walk
   Model," *Proc. IEEE ICC*, 2014, pp. 707–712.
3. Y. Xie and S.-Z. Yu, "Monitoring the Application-Layer DDoS Attacks for Popular Websites,"
   *IEEE/ACM Trans. Netw.*, vol. 17, no. 1, pp. 15–25, 2009.
