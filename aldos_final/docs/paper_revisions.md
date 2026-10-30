# Paper revisions: making the paper match the code

All numbers below were produced by `python report.py` (results, figures, tree rules,
leave-one-family-out, precision at realistic prevalence), `python redteam.py` (adversarial
tests) and `python main.py` (Table 1). The raw values are in `results/summary.json`. Every
figure and table in the revised paper should come from those files, so any number can be
reproduced on request.

**How to use this file:** each section names the part of the paper that changes, explains why,
and gives replacement text you can paste.

**One thing to decide first:** whether to state openly that this is a revised version. We
recommend it. Add a footnote under the title: *"Revised version. An earlier draft reported 100%
accuracy on a benchmark that turned out to be separable by request timing alone. Sections IV-E
and IV-F describe the corrections and an adversarial evaluation."*

---

## 1. Abstract

**Problem:** the abstract claims 100% accuracy and 0.0% FPR, and says the comparison has "five
other models". There are four other models.

**Replace the last three sentences with:**

> We evaluated the system on 10,000-session datasets reconstructed in the style of the SDSC-HTTP
> and ClarkNet-HTTP logs used in the original paper. The datasets include human-paced bots,
> attacks hidden behind normal-looking requests, bots that follow real navigation paths, and
> fast legitimate users. We compared the system against four other approaches, including a
> deep-learning neural network. Averaged over five random seeds, our system achieved 99.2%
> accuracy on both datasets and missed about 2% of attacks, against 8–59% for the other
> approaches. We then red-teamed the detector, found that attackers could evade it by splitting
> attacks across sessions, and closed that gap with server-side sessionization and cost budgets.
> Every decision traces back to readable rules.

---

## 2. Section I: Introduction, contributions list

**Change the third bullet to:**

> • A comparison against four other approaches (the original PTA, a Random Walk model, a
> deep-learning MLP and a rate threshold) on 10,000-session datasets, reported as the mean over
> five random seeds, with leave-one-attack-family-out and realistic-prevalence evaluation.

**Add two bullets:**

> • A red-team evaluation of our own detector. It found evasions through session splitting,
> website changes, decoy requests and path-following bots, and we closed or mitigated each one.
>
> • A traffic layer around the classifier:
>   - server-side sessionization;
>   - a per-client cost budget;
>   - a site-wide load guard;
>   - a page-workload model learned from server cost.

---

## 3. Section II-D: Random Walk

**Problem:** the paper says Random Walk "blocks far too many legitimate users". In our own
benchmark it had **0.0% FPR**. Its weakness was missed attacks.

**Replace the last two sentences with:**

> The original authors note that legitimate users who enter deep pages directly can look like
> deviations. In our benchmark, Random Walk raised no false alarms, but because it ignores
> timing it missed 27.0% of attacks on SDSC and 48.5% on ClarkNet: every bot whose navigation
> looked normal.

---

## 4. Section III-A: how the score is combined, and workload

**Problems:**
- The text says scores "accumulate". The implementation uses the **mean** suspicion over the
  session's transitions.
- W is described but never measured. The learned PTA used W = 1 everywhere.

**Replace "The scores accumulate across the session. If the total exceeds a threshold (θ =
0.60), the original system blocks the user immediately." with:**

> The original system accumulates these increments and blocks the session when the total
> crosses a threshold. In our implementation, the session score is the mean increment over its
> transitions, so long and short sessions are on the same scale.
>
> W is each destination page's server cost relative to an average request. In our datasets:
> checkout 3.18, cart 1.59, search 1.19, down to index 0.40 and logout 0.20. A transition never
> seen in legitimate traffic scores its page's W.
>
> Transitions involving a page that never appeared in training are skipped: a new page usually
> means the website changed, not that an attack is under way. The share of such requests is
> monitored as a signal to retrain the PTA (Section IV-F).

---

## 5. Section III-B: Stage 1

**Problems:**
- θ is not 0.60. The paper's own Table 1 gave a normal user 0.948, so the old code cleared zero
  sessions at Stage 1.
- "80% of traffic" is the share of legitimate sessions in the dataset, not what Stage 1 cleared.

**Replace the Stage 1 paragraph and code block with:**

> **Stage 1: PTA filter.** Every session is scored by the PTA, at about 0.01 ms per session.
> θ is learned as the lowest score of any attack in the training set, so Stage 1 never
> fast-paths a session that looks more normal than every attack seen in training. It also
> requires at least two scored transitions.
>
> Once bots that follow real navigation paths are part of the threat model, this rule leaves
> almost no safe fast path. On our test sets θ was 0.246 (SDSC) and 0.276 (ClarkNet), and Stage
> 1 cleared 0.4% and 0% of sessions. Stage 1's main value is therefore the evidence it passes to
> Stage 2: the PTA score and the least likely transition. At about 0.17 ms per session, running
> Stage 2 on all traffic is affordable.
>
> ```
> if len(session) < 3:                          # too short to judge alone
>     return "CHALLENGE" if site_under_load else "ALLOW"
> pta_score = compute_pta_score(session)        # Stage 1
> if scored_transitions >= 2 and pta_score < theta:
>     return "ALLOW"                            # fast path
> attack_probability = decision_tree.predict(session)
> return graded_response(attack_probability)
> ```

---

## 6. Section III-B: Stage 2 features

**Problem:** the paper describes five features. The tree now uses twelve, and its size is
chosen by cross-validation.

**Add after the five feature bullets:**

> We added seven features:
>
> - **Longest rapid streak** and **longest same-page streak.** Opening with a few
>   normal-looking requests dilutes whole-session statistics, but can't shorten a streak
>   (Section IV-F).
> - **Median think time** and **think-time coefficient of variation.** Bots keep regular timing
>   even when they slow down to human speed.
> - **Cost rate:** server cost per second, the quantity an asymmetric attacker is trying to
>   maximise.
> - **PTA score** and **minimum transition probability**, so Stage 2 uses Stage 1's evidence.
>
> The tree's depth (4–7) and minimum leaf size (10–40 sessions) are chosen by 3-fold
> cross-validation on the training data. No rule can rest on one or two examples. The selected
> trees had depth 6 (SDSC) and 7 (ClarkNet).

**Correct "Bots consistently exceed 5 per second" to:**

> Flooding bots exceed several requests per second; human-paced bots do not, which is why rate
> alone is insufficient.

---

## 7. Section III-B: new subsection, "Traffic layer"

**Add after the graded response:**

> **Traffic layer.** A per-session model can be evaded by splitting an attack into sessions too
> short to judge. Three components prevent this:
>
> 1. **Server-side sessionization.** Sessions are formed per client and end after 5 minutes of
>    inactivity or a logout, so attackers can't choose session boundaries.
> 2. **Load guard.** A site-wide meter of server cost per second. When cost exceeds twice the
>    busiest normal 10-second window, sessions too short to judge are challenged instead of
>    allowed.
> 3. **Client budget.** A client whose server cost over 10 minutes exceeds twice the costliest
>    real visitor session is challenged, even if each session looks human.

**Also change** "terminated and the IP address is added to a blacklist" to **"terminated (in
deployment, the source could also be blacklisted)"**.

---

## 8. Section III-C: the example decision tree

**Problem:** the example tree is illustrative; it isn't what the code trained.

**Replace the code block and the sentence before it with** (SDSC, simplified from
`results/tree_rules_SDSC-HTTP.txt`; counts are training sessions, legitimate / attack):

> The tree trained on SDSC-HTTP has depth 6 and 13 leaves. Its main rules:
>
> ```
> Is min_transition_prob ≤ 0.03?             (a step real users almost never take)
>   YES → ATTACK                              0 legit / 1,098 attack
>   NO  → Is longest_rapid_streak > 3.5?
>          YES → ATTACK                       3 legit / 263 attack
>          NO  → Is longest_same_page_streak > 4.5?
>                 YES → ATTACK                3 legit / 104 attack
>                 NO  → timing rules, e.g.
>                       low variance, session > 7.3 s,
>                       median think time ≤ 1.52 s → ATTACK   0 legit / 40 attack
>                       otherwise mostly LEGITIMATE
> ```
>
> The first rule alone catches 1,098 of the 1,563 training attacks. The streak rules catch floods,
> including disguised ones. The timing-regularity rule catches bots on real paths that keep
> machine-steady pacing.

---

## 9. Section III-D: Dataset setup

**Replace the second, third and fourth paragraphs with:**

> **Legitimate users.** Both datasets use eight pages:
> - SDSC-HTTP (e-commerce style): index, login, search, product, cart, checkout, profile, logout.
> - ClarkNet-HTTP (news-portal style): home, news, sports, tech, login, search, archive, logout.
>
> Legitimate users follow a Markov navigation flow (e.g. search → product → cart → checkout).
> Their think times are log-normal with a mean of about 2 s; 20% are fast "power users" with a
> median of about 1 s. Each page has an assumed relative server cost (e.g. checkout 8× index).
> In deployment, these would come from response-time logs.
>
> **Attacks.** Attack sessions cover the five attack types of the original paper, plus a sixth,
> in equal shares:
> - The original five: random flood, single-URL flood, random high-workload, single
>   high-workload URL, and scripted botnet sequence.
> - **A6, a path-following bot:** it walks the legitimate navigation flow with regular 0.05–1.0 s
>   pacing.
>
> The first five types are paced as a flood (40%), a slow bot (30%) or a human-paced but regular
> bot (30%). 30% of them open with 1–3 normal-looking requests (a decoy).
>
> **Split and seeds.** Each dataset has 10,000 sessions (80% legitimate, 20% attack): 8,000 for
> training and 2,000 for testing. The PTA is learned only from legitimate training sessions.
> Results are the mean ± standard deviation over five seeds (42, 1, 2, 3, 4). The confusion
> matrix, Table 1 and figures use seed 42.
>
> **Baselines.** The PTA Only and Random Walk thresholds are tuned to maximise F1 on the same
> training split (F1, because with 80% legitimate traffic, "never flag" maximises accuracy). The
> MLP gets the same behavioural features as our tree.

---

## 10. Section IV-A: Table 1 and its text

**Replace the paragraph and Table 1 with** (from `python main.py`):

> Table 1 shows how the detector trained on SDSC-HTTP handles eight example sessions. PTA scores
> can exceed 1 because they are weighted by page workload.
>
> - **The most important row is the fast legitimate user,** who clicks every 0.7–1.2 s. Their
>   PTA score is 1.199, so a fixed-threshold system would block them. Our Stage 2 gives a 3.9%
>   attack probability and allows them through.
> - **The slow checkout bot is caught.** It paces itself like a human, but repeats a transition
>   that real users never make.
> - **The disguised flood is caught too.** It opens with three normal pages, but that doesn't
>   affect the streak features.

| Session              | Pages                                   | PTA score | Stage | Decision | Attack prob. |
|----------------------|-----------------------------------------|----------:|-------|----------|-------------:|
| Normal shopper       | index→search→product→cart→checkout→logout (1.5–5.2 s) | 0.998 | ML | ALLOW | 0.1% |
| Checkout flood       | checkout ×6 (0.1 s)                      | 3.182     | ML    | BLOCK    | 100%         |
| Slow checkout bot    | checkout ×5 (~1.8 s)                     | 3.182     | ML    | BLOCK    | 100%         |
| Fast legitimate user | index→search→product→cart→checkout (0.7–1.2 s) | 1.199 | ML | ALLOW | 3.9% |
| Medium-risk bot      | search×2→product→search→logout (0.2–0.8 s) | 0.723   | ML    | BLOCK    | 100%         |
| Product browser      | index→product×3→search (2.0–4.1 s)       | 0.702     | ML    | ALLOW    | 0.1%         |
| Disguised flood      | index→search→product, then product ×6 (0.1 s) | 0.704 | ML | BLOCK  | 100%         |
| Hand-crafted attack  | login×2→search×2 (0.07–0.09 s)           | 0.992     | ML    | BLOCK    | 100%         |

---

## 11. Section IV-B: Table 2 and its text

**Replace the text and Table 2 with:**

> Table 2 reports each model's mean ± standard deviation over five seeds. Our hybrid system has
> the highest accuracy and F1, and the lowest miss rate, on both datasets.
>
> - **Every baseline misses a whole class of attack.** The rate threshold sees only timing, so it
>   misses human-paced bots (57–59% missed). Random Walk sees only page order, so it raises no
>   false alarms but misses bots on normal-looking paths (27–49% missed). The PTA score alone
>   separates ClarkNet traffic poorly: at its best-F1 threshold, it flags 41% of real users.
> - **The MLP is the strongest baseline,** but misses 8–10% of attacks, against about 2% for our
>   system.

**Table 2a: SDSC-HTTP (mean ± std, 5 seeds, %)**

| Model                 | Accuracy    | F1          | FPR         | FNR         |
|-----------------------|-------------|-------------|-------------|-------------|
| **Hybrid PTA+DT (ours)** | **99.2 ± 0.3** | **98.0 ± 0.7** | 0.37 ± 0.42 | **2.5 ± 1.6** |
| PTA Only [1]          | 85.5 ± 1.1  | 60.6 ± 0.8  | 6.82 ± 2.24 | 44.9 ± 4.2  |
| Random Walk [9]       | 94.5 ± 0.3  | 84.3 ± 1.4  | **0.00 ± 0.00** | 27.0 ± 2.0 |
| Deep Learning MLP     | 97.2 ± 0.5  | 92.8 ± 1.5  | 1.03 ± 0.26 | 9.9 ± 2.1   |
| Rate Threshold        | 87.5 ± 0.4  | 58.1 ± 1.1  | 1.20 ± 0.34 | 57.1 ± 0.8  |

**Table 2b: ClarkNet-HTTP (mean ± std, 5 seeds, %)**

| Model                 | Accuracy    | F1          | FPR         | FNR         |
|-----------------------|-------------|-------------|-------------|-------------|
| **Hybrid PTA+DT (ours)** | **99.2 ± 0.1** | **97.9 ± 0.3** | 0.62 ± 0.23 | **1.8 ± 1.0** |
| PTA Only [1]          | 63.4 ± 0.5  | 47.0 ± 1.7  | 40.82 ± 1.43 | 20.5 ± 3.3 |
| Random Walk [9]       | 90.1 ± 0.4  | 67.9 ± 2.6  | **0.00 ± 0.00** | 48.5 ± 3.0 |
| Deep Learning MLP     | 97.9 ± 0.2  | 94.6 ± 0.8  | 0.53 ± 0.20 | 8.3 ± 1.6   |
| Rate Threshold        | 86.5 ± 0.7  | 55.1 ± 1.7  | 1.75 ± 0.33 | 59.4 ± 1.6  |

---

## 12. Section IV-C: confusion matrix

**Replace Table 3 and the sentence after it** (seed 42; CHALLENGE and BLOCK both count as
"predicted attack"):

|                    | Predicted legitimate | Predicted attack |
|--------------------|---------------------:|-----------------:|
| **SDSC: actual legitimate**     | 1,562 | 1   |
| **SDSC: actual attack**         | 12    | 425 |
| **ClarkNet: actual legitimate** | 1,549 | 9   |
| **ClarkNet: actual attack**     | 8     | 434 |

> On SDSC, the hybrid wrongly flagged 1 of 1,563 legitimate users and missed 12 of 437 attacks,
> mostly path-following bots (A6: 87.9% detected). On ClarkNet, it wrongly flagged 9 of 1,558
> and missed 8 of 442.

---

## 13. Section IV-D: figures (replace all five)

Use the PNGs in `results/`. New captions:

- **Figure 1** (`fig1_accuracy_f1.png`): Accuracy and F1 for all five models on both datasets
  (seed 42).
- **Figure 2** (`fig2_error_rates.png`): False positive rate (legitimate users flagged) and false
  negative rate (attacks missed) for each model.
- **Figure 3** (`fig3_pta_scores.png`): Stage 1 PTA scores on the test sets, with the learned θ.
  Legitimate and attack scores overlap heavily between 0.3 and 1.5, because bots on real paths
  score like real users. Only a few legitimate sessions fall below θ. This is why Stage 2, not
  the PTA threshold, makes almost every decision.
- **Figure 4** (`fig4_latency.png`): Processing time per session.
  - The Stage 1 path takes about 0.01 ms.
  - The full hybrid takes 0.16–0.18 ms.
  - Called one session at a time, as on a live server, the MLP takes about 0.29 ms.
  - Batched, the MLP takes 0.07–0.08 ms per session, which isn't possible when each session
    needs an immediate decision.

  These timings come from single-threaded Python on one laptop.
- **Figure 5** (`fig5_decisions.png`): what the hybrid decided on 2,000 test sessions.

  | | Allowed at Stage 1 | Allowed at Stage 2 | Challenged | Blocked |
  |---|---|---|---|---|
  | SDSC | 0.4% | 78.3% | 0% | 21.3% |
  | ClarkNet | 0% | 77.9% | 0.6% | 21.6% |

---

## 14. Table 4: capability comparison

**Replace with:**

| Capability                     | Ours    | PTA Only | Random Walk | MLP     | Rate Threshold |
|--------------------------------|---------|----------|-------------|---------|----------------|
| Catches fast bots              | Yes     | Yes      | Partly      | Yes     | Yes            |
| Catches human-paced bots       | Yes     | Partly   | Partly      | Partly  | No             |
| Catches path-following bots    | Mostly (88–93%) | No | No       | Partly  | Partly         |
| Catches decoy-prefixed floods  | Yes     | Partly   | Partly      | Partly  | No             |
| Resists session splitting      | Yes (traffic layer) | No | No     | No      | No             |
| Robust to website changes      | Yes (unknown pages skipped) | No | No | n/a | n/a        |
| Graded response                | Yes (rarely triggered, §V-C) | No | No | No | No             |
| Explainable decisions          | Full    | Partial  | Partial     | No      | Full           |
| Low false positives            | Yes     | No       | Yes         | Yes     | Yes            |
| Low missed attacks             | Yes     | No       | No          | No      | No             |

---

## 15. Section IV-E (new): corrections to the earlier draft

**Add:**

> **E. Corrections to the earlier draft.** An earlier version of this paper reported 100%
> accuracy and 0.0% FPR. Auditing that evaluation found three problems:
>
> 1. **Attack timing alone separated the classes.** A one-line rate threshold also scored 100%.
> 2. **The PTA was never learned for the benchmark sites,** so PTA Only and Random Walk flagged
>    every session (19% accuracy). That reflected our setup, not those methods.
> 3. **The fixed θ = 0.60 was below even normal users' scores,** so Stage 1 never cleared a
>    session.
>
> We rebuilt the benchmark with realistic navigation, varied pacing and harder attacks, learned
> the PTA and θ from training data, and tuned every baseline on the same split.

---

## 16. Section IV-F (new): adversarial evaluation

**Add:**

> **F. Red-teaming the detector.** We attacked our own detector in eight ways (`redteam.py`).
>
> | Attack | Before | After the fix |
> |---|---|---|
> | Splitting into 2-request sessions, one IP | 100% allowed | 0% allowed |
> | 3,000-IP botnet, 1 request each | allowed | 1% allowed; real users 1.3% challenged, 0.2% blocked |
> | Website adds one page | 26.8% of real users flagged | 0.2% flagged; drift monitor reports 5.3% unknown pages |
> | Decoy page, then flood | allowed | blocked |
> | Path-following bot, 0.5–1.0 s | 0.8% caught | 51.8% per session |
> | Human-paced bot, running continuously | never caught | challenged after 21 requests |
>
> **The fixes:**
> - Session splitting: server-side sessionization, the load guard and the client budget.
> - Website changes: skipping unknown pages, plus a drift monitor.
> - Decoy floods: the streak features.
> - Path-following bots: attack type A6 and the timing-regularity features.
>
> **Generalisation.** Trained without A6 examples, the detector caught only 2.7–34.5% of A6 bots.
> It recognises the attacks it was trained on, so new strategies need new data.
>
> **Poisoning.** With 50% of training attacks mislabelled as legitimate, it missed 18.5% of
> attacks.

---

## 17. Section V-A: what the results mean

**Replace with:**

> The hybrid wins because it combines kinds of evidence that each catch a different attack:
> - **Page order:** transitions real users never make.
> - **Timing:** rapid streaks and machine-regular pacing.
> - **Cost:** expensive pages per second.
>
> Each baseline sees one kind and misses the others. These results come from synthetic data,
> including assumed page costs. They show that the design works under the conditions we
> modelled, not how it would perform on real traffic.

---

## 18. Section V-B: advantage over deep learning

**Replace "Both our system and the deep learning MLP achieve 100% accuracy, so why prefer
ours?" with:**

> Our system outperformed the MLP on both datasets, with the same behavioural features:
> - Accuracy: 99.2% vs 97.2% (SDSC) and 99.2% vs 97.9% (ClarkNet).
> - Missed attacks: about 2% vs 8–10%.
>
> The main reason is that our tree also receives the PTA's page-order evidence. Beyond accuracy,
> there are three reasons to prefer the hybrid.

**Replace the "Second, efficiency" paragraph with:**

> Second, per-session cost. Evaluated one session at a time, as a live server must, the full
> hybrid took 0.16–0.18 ms per session against about 0.29 ms for the MLP. Contrary to our
> earlier draft, Stage 1 rarely fast-paths traffic: with path-following bots in the threat model,
> a θ that never admits a training attack clears almost nothing. Its value is the evidence it
> gives Stage 2.

---

## 19. Section V-C: limitations

**Replace the θ paragraph with:**

> θ is learned as the lowest training-attack score. That guarantees no training attack is
> fast-pathed, but with path-following bots it leaves almost no fast path (0–0.4% of sessions).

**Add these paragraphs:**

> **The graded response is rarely exercised.** CHALLENGE fired for 0 of 2,000 SDSC and 12 of
> 2,000 ClarkNet test sessions, because almost all tree leaves are nearly pure. Calibrated
> probabilities, tuned on real traffic, are needed to evaluate it properly.
>
> **Precision at realistic prevalence.** If 0.1% of sessions are attacks, only 60% (SDSC) and 34%
> (ClarkNet) of blocked sessions would be attacks. Low-confidence flags should therefore be
> challenges, and false-positive rates must be measured on real traffic.
>
> **Human-paced bots** can't be detected within a single session. Only the client budget catches
> them, after about a minute. A botnet of them resembles a flash crowd.

---

## 20. Section VI: conclusion

**Replace the sentence claiming "100% detection accuracy, 0.0% false positive rate…" with:**

> In our evaluation, the system had the highest accuracy and lowest miss rate of the five
> approaches compared on both datasets. With its traffic layer, it also withstood the session
> splitting, site-change and decoy attacks we found by red-teaming it, while keeping decisions
> traceable to readable rules.

**Update the Future Work bullets:**

> • Evaluate on real logs, with response times as page costs.
>
> • Calibrate probabilities so the CHALLENGE band reflects genuine uncertainty.
>
> • Generate adversarial attacks automatically and retrain on what gets through.
>
> • Add cross-session reputation (cookies, device fingerprints) for human-paced botnets.
