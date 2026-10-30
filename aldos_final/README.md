# Hybrid PTA + Decision Tree for Application-Layer DDoS Detection

A two-stage detector for **asymmetric application-layer DDoS attacks**: bots that take a web
server down with a small number of valid-looking requests to its most expensive pages.

- **Stage 1** is a **Probabilistic Timed Automaton (PTA)**, the model from Praseed & Thilagam
  (IEEE TIFS, 2021). It quickly clears sessions that look clearly normal.
- **Stage 2** is a **Decision Tree** that gives each suspicious session an attack probability.
- **Graded response:** that probability maps to **Allow / Challenge (CAPTCHA) / Block** instead
  of the original system's binary block-or-allow.

**Authors:** Tamirah Goode, Keila Chavez, Taiwo Ojo. CSIT 540 (Computer Networks Security),
Montclair State University.
**Paper:** *A Hybrid PTA and Decision Tree Framework for Application Layer DDoS Detection with
Graded Response* ([`Final_Research_Paper.docx.pdf`](Final_Research_Paper.docx.pdf)).

> **Note on results:** the paper reports 100% accuracy for the first version (v1) of this code.
> After writing it, we found that the benchmark behind those numbers was flawed, fixed it, and
> re-ran everything. This README reports the corrected (v2) results. See
> [From the paper to v2](#from-the-paper-to-v2) for what changed and why.

---

## The problem

A firewall inspects individual requests, but in this attack every request is valid. A bot that
calls `/checkout` again and again sends nothing malformed. The only signal is **behaviour across
the whole session**: which pages are visited in what order, how long the client waits between
clicks, and how expensive those pages are to serve.

Praseed & Thilagam's PTA learns that behaviour from server logs and gives every session a
suspicion score, but its decision is binary. A fast human who crosses the threshold gets blocked,
and a careful bot that stays just under it gets through. This project adds a second, explainable
stage and a middle "challenge" option.

---

## Architecture

```
                 session = [(page, think_time), ...]
                                  │
                ┌─────────────────▼──────────────────┐
  Stage 1       │  PTA suspicion score (every session)│
                │  mean over transitions of           │
                │  W · (1 − P_trans · P_think)        │
                └─────────────────┬──────────────────┘
                  score < θ       │       score ≥ θ
             ┌────────────────────┴───────────────────┐
             ▼                                        ▼
          ALLOW                     ┌──────────────────────────────────┐
     (no ML cost)        Stage 2    │ Decision Tree → attack probability│
                                    └────────────────┬─────────────────┘
                                 < 35%          35–70%           ≥ 70%
                                 ALLOW        CHALLENGE          BLOCK
```

### Stage 1: PTA

The PTA is a directed graph learned from **legitimate** sessions. For each transition
`page i → page j` it stores:

- **`P_trans`**: the transition probability, `n_ij / Σ_k n_ik`.
- **Think-time statistics**: mean `μ` and spread `σ`.
- **Workload `W`**: the relative server cost.

Each step of a session is scored:

```
P_think   = exp(−|t − μ| / σ)
suspicion = W · (1 − P_trans · P_think)       # unknown transition → 1.0
```

The session's score is the mean over its transitions. The threshold **θ is learned**: it is set
to the lowest score of any attack in the training data, so Stage 1 only fast-paths sessions that
look more normal than every attack seen in training.

### Stage 2: Decision Tree (depth 5)

| Feature               | Captures                                            |
|-----------------------|-----------------------------------------------------|
| `request_rate`        | Requests per second over the session                |
| `think_time_variance` | Bots are regular; humans vary                       |
| `page_repetition`     | Share of requests hitting the most-requested page   |
| `session_duration`    | Total time of the session                           |
| `rapid_requests`      | Requests with < 0.5 s think time                    |
| `longest_rapid_streak` | Longest run of consecutive < 0.5 s requests        |
| `longest_same_page_streak` | Longest run of consecutive requests to one page |
| `pta_score`           | Stage 1 score (page-order + timing evidence)        |
| `min_transition_prob` | How unlikely the session's rarest step is           |

The two **streak** features were added after we found an evasion by testing our own model: an
attacker who opens with a few normal-looking pages dilutes whole-session statistics like
`page_repetition`. A decoy prefix can't shorten a streak, though. See
[Red-teaming](#red-teaming).

We chose a Decision Tree over a neural network so that **every decision can be traced to
readable if/then rules**, which can be audited, explained to a blocked user, or shown to a
regulator.

### Graded response

| Attack probability | Decision    | Action                              |
|--------------------|-------------|-------------------------------------|
| < 35%              | `ALLOW`     | Proceed                             |
| 35–70%             | `CHALLENGE` | CAPTCHA or temporary rate limit     |
| ≥ 70%              | `BLOCK`     | Terminate the session               |

---

## Results (v2)

Each dataset has 10,000 sessions (80% legitimate, 20% attack), split 8,000 for training and
2,000 for testing. Every model that needs training is trained on the same split. The table
shows the **mean ± standard deviation over 5 random seeds**. Every number and figure is
reproduced by `python report.py`.

| Model                        | SDSC Accuracy | SDSC F1   | SDSC FPR | SDSC FNR | ClarkNet Accuracy | ClarkNet F1 | ClarkNet FPR | ClarkNet FNR |
|------------------------------|---------------|-----------|----------|----------|-------------------|-------------|--------------|--------------|
| **Hybrid PTA + DT (ours)**   | **99.8 ± 0.1** | **99.5 ± 0.2** | **0.0 ± 0.0** | **0.9 ± 0.5** | **99.7 ± 0.1** | **99.1 ± 0.3** | 0.2 ± 0.1 | **1.1 ± 0.5** |
| PTA Only (Praseed 2021)      | 92.1 ± 0.3    | 80.6 ± 1.3 | 5.8 ± 0.5 | 16.7 ± 3.5 | 82.3 ± 0.9     | 34.3 ± 1.9  | 2.5 ± 0.4    | 77.2 ± 1.6   |
| Random Walk (Xu et al. 2014) | 97.4 ± 0.2    | 92.8 ± 0.6 | **0.0 ± 0.0** | 13.4 ± 1.1 | 92.2 ± 1.0 | 76.2 ± 2.9  | **0.0 ± 0.0** | 38.3 ± 3.8  |
| Deep Learning (MLP 64-32-16) | 96.0 ± 0.1    | 89.4 ± 0.5 | 1.2 ± 0.1 | 15.2 ± 0.9 | 97.2 ± 0.4     | 92.9 ± 1.0  | 0.7 ± 0.2    | 10.9 ± 1.9   |
| Rate Threshold (1.8 req/s)   | 86.4 ± 0.1    | 50.8 ± 0.9 | 1.1 ± 0.1 | 64.4 ± 1.0 | 85.5 ± 0.5     | 49.8 ± 2.2  | 1.6 ± 0.3    | 64.7 ± 2.2   |

All values are percentages.

**Takeaways:**

- **The hybrid has the best accuracy, F1 and miss rate on both datasets.** It misses about 1% of
  attacks; every other model misses 10–77%.
- **Each signal alone misses an attack type, and the hybrid uses both.**
  - Rate Threshold looks only at timing, so it misses about 64% of attacks: human-paced bots and
    floods hidden behind a decoy.
  - Random Walk looks only at page order, so it never raises a false alarm but misses bots whose
    navigation looks normal.
- **Only Random Walk has fewer false alarms.** On ClarkNet the hybrid's FPR is 0.2%, against
  0.0% for Random Walk, and Random Walk misses 38% of attacks.
- **The trained tree is readable** ([`results/tree_rules_*.txt`](results/)). Its first rule,
  "the session contains a transition real users almost never make", catches 1,379 of 1,600
  training attacks on SDSC.
- **Stage 1 is safe but clears little.** The learned θ cleared 6.3% (SDSC) and 5.6% (ClarkNet)
  of test sessions, with no attacks among them.
- **Per-session cost, timed one session at a time:**

  | Path                             | ms per session |
  |----------------------------------|----------------|
  | Stage 1 fast path                | ~0.01          |
  | Full hybrid                      | ~0.12          |
  | MLP, one session at a time       | ~0.22          |
  | MLP, batched (not possible live) | 0.02–0.04      |

---

## Red-teaming

After the results above were first produced, we tried to evade our own detector. One normal
page followed by six `product` requests 0.1 s apart was **allowed with 0% attack probability**:

- Every flood in the training data hit a single page from start to finish, so the tree had
  learned "almost all requests on one page" as the flood signal.
- One decoy page dropped that share below the tree's cut-off.

**The fix:**

- 30% of benchmark attacks now open with 1–3 normal-looking pages.
- We added the two streak features, which a decoy prefix can't dilute.
- The MLP baseline gets the same features, so the comparison stays fair.

After retraining, the detector blocks all of the following:

- decoy + flood (with 1 or 3 decoy pages)
- flood + decoy suffix
- floods that alternate between two pages
- 0.6 s-paced floods, just above the "rapid" cut-off
- human-paced single-page bots

It still allows a 3-request session with two fast clicks: too short to call, and it looks just
like a user double-clicking.

---

## From the paper to v2

| | Paper (v1) | This code (v2) |
|---|---|---|
| PTA used on SDSC/ClarkNet | Hand-written `login/dashboard/...` graph; the benchmark sites' pages were unknown to it | Learned per dataset from legitimate training sessions |
| Stage 1 threshold θ | Fixed at 0.60 | Learned from the training data (the paper's future work, §VI) |
| Baseline thresholds | Fixed (0.55, 0.35) | Tuned on the training split, same PTA as ours |
| Attack timing | Every attack 0.05–0.20 s apart | 40% flood, 30% slow bot, 30% human-paced; 30% open with a decoy |
| Legitimate navigation | Random pages | Realistic flows (e.g. search → product → cart → checkout), plus 20% fast "power users" |
| Stage 2 features | 5 behavioural | 7 behavioural (incl. 2 streak features) + 2 PTA features |
| Demo detector | Trained on a small toy set | The same detector as the SDSC benchmark |
| Headline result | 100% accuracy, 0% FPR | 99.8% / 99.7% accuracy, 0.0% / 0.2% FPR (5-seed mean) |
| Figures, Stage 1 coverage, latency | Not generated by the code | Measured by `report.py` |

**Why we changed it:**

- **Timing alone separated the classes in v1.** Even a one-line rate threshold scored 100%, so
  the benchmark couldn't tell good detectors from bad ones.
- **The v1 baselines weren't a fair comparison.** PTA Only and Random Walk scored 19% because
  they were run against a graph that didn't contain the benchmark sites' pages. That was our
  setup error, not a weakness of those methods.
- **Stage 1 never fast-pathed anything in v1.** Even normal users scored above 0.60 (Table 1 of
  the paper shows 0.948 for a normal user), so every session went to the tree.

The v2 numbers are lower but meaningful: the hybrid now wins because it combines two kinds of
evidence, not because the data was easy.

[`docs/paper_revisions.md`](docs/paper_revisions.md) lists every paper section affected by these
changes, with replacement text based on the measured results.

---

## Datasets

The original SDSC-HTTP and ClarkNet-HTTP logs aren't readily available, so
[`pta/datasets.py`](pta/datasets.py) reconstructs sessions in their style.

- **SDSC-HTTP:** e-commerce-like pages (`index`, `login`, `search`, `product`, `cart`,
  `checkout`, `profile`, `logout`).
- **ClarkNet-HTTP:** news-portal pages (`home`, `news`, `sports`, `tech`, `login`, `search`,
  `archive`, `logout`).

**Legitimate users** follow a Markov navigation flow. Their think times are log-normal (mean
≈ 2 s), and 20% are fast power users (median ≈ 1 s).

**Attacks** use the paper's five types:

| Type | Attack                                             |
|------|----------------------------------------------------|
| A1   | Random flood                                       |
| A2   | Single-URL flood                                   |
| A3   | Random asymmetric (high-workload pages)            |
| A4   | Single-URL asymmetric (`checkout`)                 |
| A5   | Botnet (repeated scripted sequence)                |

Each attack session gets one pacing: flood, slow bot, or human-paced but regular. 30% of attack
sessions open with 1–3 normal-looking pages (a decoy).

---

## Project structure

```
aldos_final/
├── main.py                  # Demo (8 sample sessions + batch) and full benchmark
├── demo.py                  # Interactive: test your own sessions (python -i demo.py)
├── report.py                # Measures every paper number/figure → results/
├── Final_Research_Paper.docx.pdf  # The paper (v1 results; see docs/paper_revisions.md)
├── hybrid_detector.py       # HybridDetector: fit / train / evaluate_session / explain
├── requirements.txt         # numpy, scikit-learn, networkx, matplotlib
├── results/                 # summary.json, fig1–fig5 PNGs, tree_rules_*.txt
├── docs/
│   └── paper_revisions.md   # Section-by-section corrections to the paper
└── pta/
    ├── pta_model.py         # PTAModel: networkx DiGraph; learn() builds it from sessions
    ├── scoring.py           # P_think, per-transition suspicion, session score, min transition prob
    ├── train_model.py       # MLModel: feature extraction + DecisionTreeClassifier
    ├── datasets.py          # SDSC / ClarkNet style dataset generators (benchmark)
    ├── simulate_data.py     # Small toy set used by detector.train() (not the demo)
    └── models_comparison.py # Baselines, threshold tuning, metrics, comparison table
```

---

## Running it

Requires Python 3.8+.

```bash
cd aldos_final
pip install -r requirements.txt
python main.py          # on Windows, use "py main.py" if python isn't on PATH
python -i demo.py       # interactive: check([("checkout", 0.1)] * 6)
python report.py        # regenerate results/ (a few minutes, including the 5-seed sweep)
```

`main.py` takes about 10 seconds and prints:

1. **Eight sample sessions** scored by the SDSC-trained detector. Each shows its PTA score, the
   stage that decided, the decision, and the attack probability. The sessions include a fast
   legitimate user, a slow bot and a disguised flood.
2. **Ten held-out test sessions**, with their true labels: 6 random, plus examples of the
   Stage 1 fast path and of `CHALLENGE`.
3. **A five-model comparison** on each dataset.
4. **A summary table.**

### Using the detector

```python
from hybrid_detector import HybridDetector

detector = HybridDetector()
detector.fit(train_sessions, train_labels)      # labels: 0 = legitimate, 1 = attack

detector.evaluate_session([("login", 0.08), ("login", 0.09), ("search", 0.07)])
# {'pta_score': ..., 'stage': 'ML', 'decision': 'BLOCK', 'risk': 'HIGH', 'attack_prob': ...}
```

`print(detector.explain())` prints the trained tree as if/then rules.
`detector.train(n_samples)` fits on a small toy set from `simulate_data.py`. It's quick, but
too small to give a stable tree, so the demos use the SDSC-trained detector instead.

---

## Limitations

- **The data is synthetic.** The results depend on the flows and timing distributions in
  `datasets.py`. Validating on real logs (SDSC, ClarkNet, CAIDA) is the most important next step.
- **Sessions are evaluated in isolation.** A distributed attacker can keep every session
  harmless-looking. Tracking behaviour per IP across sessions would close this gap.
- **`CHALLENGE` is rare:** 1 (SDSC) and 4 (ClarkNet) of 2,000 test sessions. Most tree leaves
  contain only one class, so probabilities are almost always 0% or 100%. These datasets contain
  few genuinely ambiguous sessions. Real traffic and calibrated probabilities are needed to
  evaluate the graded response properly.
- **Red-teaming covered only the evasions we thought of.** A supervised model catches the attacks
  it was trained on; a new evasion strategy may need new training data or features.
- **The learned θ can admit disguised bots.** An attack that scores lower than every training
  attack is allowed at Stage 1. On the benchmark test sets this never happened.
- **Single-request sessions score 0 and are always cleared,** because there's no transition to
  score.
- **The timings are rough.** They come from single-threaded Python on one laptop and vary by
  about 10% between runs.

## Future work

- Evaluate on real logs.
- Track behaviour across sessions per IP.
- Calibrate probabilities so `CHALLENGE` is used more.
- Push `BLOCK` decisions to an SDN controller.
- Model HTTP/2 multiplexed sessions (see Praseed & Thilagam, TIFS 2020).

## References

1. A. Praseed and P. S. Thilagam, "Modelling Behavioural Dynamics for Asymmetric Application Layer
   DDoS Detection," *IEEE Trans. Inf. Forensics Security*, vol. 16, pp. 617–626, 2021.
2. C. Xu, G. Zhao, G. Xie, and S. Yu, "Detection on Application Layer DDoS Using Random Walk
   Model," *Proc. IEEE ICC*, 2014, pp. 707–712.
3. Y. Xie and S.-Z. Yu, "Monitoring the Application-Layer DDoS Attacks for Popular Websites,"
   *IEEE/ACM Trans. Netw.*, vol. 17, no. 1, pp. 15–25, 2009.
