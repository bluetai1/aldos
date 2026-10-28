# Paper revisions: making the paper match the code

All numbers below were produced by `python report.py` (results, figures, tree rules) and
`python main.py` (Table 1). The raw values are in `results/summary.json`. Every figure and table in
the revised paper should come from those files, so any number can be reproduced on request.

**How to use this file:** each section names the part of the paper that changes, explains why,
and gives replacement text you can paste.

**One thing to decide first:** whether to state openly that this is a revised version. We
recommend it. Add a footnote under the title: *"Revised version. An earlier draft reported 100%
accuracy on a benchmark that turned out to be separable by request timing alone. Section IV-E
describes the corrections."*

---

## 1. Abstract

**Problem:** the abstract claims 100% accuracy and 0.0% FPR, and says the comparison has "five
other models". There are four other models.

**Replace the last three sentences with:**

> We evaluated the system on 10,000-session datasets reconstructed in the style of the SDSC-HTTP
> and ClarkNet-HTTP logs used in the original paper. The datasets include human-paced bots and
> fast legitimate users, so that no single signal separates the classes. We compared the system
> against four other approaches, including a deep-learning neural network. Averaged over five
> random seeds, our system achieved 99.7% and 98.4% accuracy, with the lowest miss rates of any
> model (1.4% and 2.1%), and every decision traces back to readable rules.

---

## 2. Section I: Introduction, contributions list

**Problem:** the third bullet says "five other models".

**Change it to:**

> • A comparison against four other approaches (the original PTA, a Random Walk model, a
> deep-learning MLP and a rate threshold) on 10,000-session datasets, reported as the mean over
> five random seeds.

---

## 3. Section II-D: Random Walk

**Problem:** the paper says Random Walk "blocks far too many legitimate users". In our own
benchmark it had **0.0% FPR**. Its weakness was missed attacks (FNR 15.8% and 44.9%). Our
legitimate users don't include deep-link visitors arriving from search engines, so we can't
support the false-positive claim with data.

**Replace the last two sentences with:**

> The original authors note that legitimate users who enter deep pages directly (for example
> from a search engine) can look like deviations. In our benchmark, Random Walk raised no false
> alarms, but because it ignores timing it missed every bot whose navigation looked normal:
> 15.8% of attacks on SDSC and 44.9% on ClarkNet.

---

## 4. Section III-A: how the score is combined

**Problem:** the text says "the scores accumulate across the session". Our implementation uses
the **mean** suspicion over the session's transitions, so the score doesn't grow with session
length.

**Replace "The scores accumulate across the session. If the total exceeds a threshold (θ =
0.60), the original system blocks the user immediately." with:**

> The original system accumulates these increments and blocks the session when the total
> crosses a threshold. In our implementation, the session score is the mean increment over its
> transitions, so long and short sessions are on the same scale. A transition never seen in
> legitimate traffic scores the maximum, 1.0.

---

## 5. Section III-B: Stage 1

**Problem:** the paper says θ = 0.60 and that Stage 1 clears "80% of traffic". Neither is true:
- **θ:** the paper's own Table 1 gave a *normal* user a score of 0.948. With θ = 0.60, the old
  code cleared **zero** sessions at Stage 1.
- **80%:** that figure is the share of legitimate sessions in the dataset, not what Stage 1
  cleared.

**Replace the Stage 1 paragraph and code block with:**

> **Stage 1: PTA filter.** Every session is scored by the PTA first. This is cheap: one formula
> per page transition, measured at 0.009–0.013 ms per session.
>
> Instead of a fixed threshold, θ is learned from the training data. It is set to the lowest
> score of any attack session in the training set, so Stage 1 only fast-paths sessions that look
> more normal than every attack seen in training. This makes Stage 1 deliberately conservative:
> - On the SDSC test set (θ = 0.669) it cleared 12.8% of all sessions (16.0% of legitimate users).
> - On ClarkNet (θ = 0.674) it cleared 3.4% (4.2% of legitimate users).
> - On both datasets, no attack was cleared at Stage 1.
>
> All other sessions go to Stage 2.
>
> ```
> pta_score = compute_pta_score(session)       # Stage 1, every session
> if pta_score < theta:                        # theta learned from training data
>     return "ALLOW"                           # fast path, no ML
> attack_probability = decision_tree.predict(session)
> return graded_response(attack_probability)
> ```

---

## 6. Section III-B: Stage 2 features

**Problem:** the paper says five features. On the benchmark, the tree also gets two features
from the PTA.

**Add after the five feature bullets:**

> On the benchmark datasets, Stage 2 also gets two features from the PTA, so the page-order
> evidence from Stage 1 isn't thrown away:
> - **PTA score:** the Stage 1 suspicion score.
> - **Minimum transition probability:** how likely the least likely step in the session is
>   (0 if real users never take it).
>
> Without these two features the tree reached only 95.4% accuracy on SDSC, below the Random Walk
> model.

**Also correct "Bots consistently exceed 5 per second".** Human-paced bots in our data don't do
this. Replace it with:

> Flooding bots exceed several requests per second; human-paced bots do not, which is why rate
> alone is insufficient.

---

## 7. Section III-B: Graded response, "IP address is added to a blacklist"

The code returns a decision; it doesn't blacklist anything. Change "terminated and the IP
address is added to a blacklist" to **"terminated (in deployment, the source could also be
blacklisted)"**.

---

## 8. Section III-C: the example decision tree

**Problem:** the example tree (rapid_request_count > 3, 98.4% confidence, …) is illustrative;
it isn't what the code trained. An interviewer may ask to see the real tree.

**Replace the code block and the sentence before it with the real tree** (SDSC, simplified from
`results/tree_rules_SDSC-HTTP.txt`; the counts are training sessions, legitimate / attack):

> The tree trained on SDSC-HTTP has depth 5 and 11 leaves. Its main rules:
>
> ```
> Is min_transition_prob ≤ 0.03?        (a step real users almost never take)
>   YES → ATTACK                         0 legit / 1,363 attack
>   NO  → Is page_repetition ≤ 0.92?
>          YES → Is request_rate ≤ 4.81 req/s?
>                 YES → Is rapid_requests ≤ 5.5?
>                        YES → LEGITIMATE   6,276 legit / 16 attack
>                 NO  → ATTACK               0 legit / 12 attack
>          NO  → Is pta_score ≤ 0.87?
>                 YES → LEGITIMATE           119 legit / 0 attack
>                 NO  → Is think_time_variance ≤ 0.89?
>                        YES → ATTACK        2 legit / 204 attack
> ```
>
> The first rule alone catches 1,363 of the 1,597 training attacks. Every one of them contained
> a page transition that legitimate users essentially never make.

---

## 9. Section III-D: Dataset setup

**Problems:**
- The page distributions describe the old generator, where legitimate users picked pages at
  random. They now follow navigation flows.
- The "grey-area sessions" paragraph describes `simulate_data.py`, which is the demo's data, not
  the benchmark's.
- The SDSC site is described as an "academic web server", but its pages are e-commerce pages.

**Replace the second, third and fourth paragraphs with:**

> **Legitimate users.** Both datasets use eight pages:
> - SDSC-HTTP (e-commerce style): index, login, search, product, cart, checkout, profile, logout.
> - ClarkNet-HTTP (news-portal style): home, news, sports, tech, login, search, archive, logout.
>
> Legitimate users follow a Markov navigation flow (e.g. search → product → cart → checkout) and
> start on a page drawn from the access frequencies above. Their think times are log-normal with
> a mean of about 2 s. Twenty percent are fast "power users" with a median of about 1 s.
>
> **Attacks.** Attack sessions follow the five attack types of the original paper: random flood,
> single-URL flood, random high-workload, single high-workload URL, and scripted botnet sequence.
> To prevent timing alone from separating the classes, each attack session gets one pacing:
> - 40% flood (0.05–0.20 s between requests).
> - 30% are slow bots (0.3–1.1 s).
> - 30% are paced like humans (about 1.7 s) but more regular than real users.
>
> **Split and seeds.** Each dataset has 10,000 sessions (80% legitimate, 20% attack): 8,000 for
> training and 2,000 for testing. The PTA is learned only from legitimate training sessions. All
> results are the mean ± standard deviation over five random seeds (42, 1, 2, 3, 4), except the
> confusion matrix and figures, which use seed 42.
>
> **Baseline tuning.** The PTA Only and Random Walk thresholds are tuned on the same training
> split, using the same learned PTA, so all models are compared on equal terms.

---

## 10. Section IV-A: Table 1 and its text

**Problem:** the PTA scores in the old table come from the hand-written graph. The story about
the fast legitimate user (0.871, sent to Stage 2, 6.2% attack probability) no longer matches what
the code does.

**Replace the paragraph and Table 1 with** (from `python main.py`):

> Table 1 shows how the system handles eight example sessions. The demo detector is trained on a
> small simulated set (382 sessions), and its learned θ clears both legitimate examples at
> Stage 1 without calling the classifier. One of them is a fast user clicking every 0.5–0.8 s.
> A fixed-threshold system would flag this user, since the score of 0.847 is above 0.60. All five
> attack sessions go to Stage 2 and are blocked. The "Noisy normal" user goes to Stage 2, which
> correctly allows them (0% attack probability).

| Session            | PTA score | Stage | Decision | Attack prob. |
|--------------------|----------:|-------|----------|-------------:|
| Normal user        | 0.666     | PTA   | ALLOW    | —            |
| DDoS attacker      | 0.963     | ML    | BLOCK    | 100%         |
| Slow bot           | 0.922     | ML    | BLOCK    | 100%         |
| Fast legit user    | 0.847     | PTA   | ALLOW    | —            |
| Medium-risk bot    | 0.959     | ML    | BLOCK    | 100%         |
| Noisy normal user  | 0.884     | ML    | ALLOW    | 0%           |
| Noisy attack bot   | 0.914     | ML    | BLOCK    | 100%         |
| Hand-crafted attack| 0.990     | ML    | BLOCK    | 100%         |

---

## 11. Section IV-B: Table 2 and its text

**Problem:** all the numbers have changed. Also, the 19% for PTA Only and Random Walk came from a
setup error in our experiment (the graph didn't contain the benchmark sites' pages), not from a
weakness of those methods.

**Replace the text and Table 2 with:**

> Table 2 reports each model's mean ± standard deviation over five seeds. Our hybrid system has
> the highest accuracy and F1 and the lowest miss rate on both datasets.
>
> - **The baselines fail in opposite ways.** The rate threshold sees only timing, so it misses
>   the roughly 58% of attacks that are human-paced. Random Walk sees only page order, so it
>   never raises a false alarm but misses bots whose navigation looks normal.
> - **The hybrid wins by combining both kinds of evidence.** Behavioural statistics and the
>   PTA's page-order evidence go into the same classifier.
> - **The trade-off is false positives on ClarkNet.** The hybrid's FPR there is 1.5%, against
>   0.5% for the MLP. Part of this is because a CHALLENGE counts as an attack prediction.

**Table 2a: SDSC-HTTP (mean ± std, 5 seeds)**

| Model                 | Accuracy    | F1          | FPR        | FNR         |
|-----------------------|-------------|-------------|------------|-------------|
| **Hybrid PTA+DT (ours)** | **99.7 ± 0.1** | **99.2 ± 0.3** | 0.1 ± 0.0 | **1.4 ± 0.5** |
| PTA Only [1]          | 92.6 ± 0.5  | 82.1 ± 1.3  | 5.3 ± 0.4  | 15.9 ± 2.6  |
| Random Walk [9]       | 96.8 ± 0.2  | 91.4 ± 0.6  | **0.0 ± 0.0** | 15.8 ± 1.0 |
| Deep Learning MLP     | 95.4 ± 0.3  | 88.1 ± 0.9  | 1.6 ± 0.5  | 16.2 ± 2.6  |
| Rate Threshold        | 87.4 ± 0.3  | 57.0 ± 2.0  | 0.9 ± 0.3  | 58.6 ± 2.1  |

**Table 2b: ClarkNet-HTTP (mean ± std, 5 seeds)**

| Model                 | Accuracy    | F1          | FPR        | FNR         |
|-----------------------|-------------|-------------|------------|-------------|
| **Hybrid PTA+DT (ours)** | **98.4 ± 0.6** | **96.1 ± 1.1** | 1.5 ± 0.7 | **2.1 ± 1.1** |
| PTA Only [1]          | 83.0 ± 0.5  | 38.1 ± 1.6  | 2.6 ± 0.5  | 74.0 ± 1.7  |
| Random Walk [9]       | 90.9 ± 0.5  | 71.1 ± 1.5  | **0.0 ± 0.0** | 44.9 ± 1.7 |
| Deep Learning MLP     | 97.6 ± 0.4  | 93.9 ± 1.0  | 0.5 ± 0.2  | 9.8 ± 2.0   |
| Rate Threshold        | 86.8 ± 0.6  | 56.2 ± 1.7  | 1.9 ± 0.4  | 58.0 ± 2.2  |

---

## 12. Section IV-C: confusion matrix

**Replace Table 3 and the sentence after it** (seed 42; CHALLENGE and BLOCK both count as
"predicted attack"):

|                    | Predicted legitimate | Predicted attack |
|--------------------|---------------------:|-----------------:|
| **SDSC: actual legitimate**     | 1,595 | 2   |
| **SDSC: actual attack**         | 8     | 395 |
| **ClarkNet: actual legitimate** | 1,587 | 13  |
| **ClarkNet: actual attack**     | 15    | 385 |

> On SDSC, the hybrid wrongly flagged 2 of 1,597 legitimate users and missed 8 of 403 attacks. On
> ClarkNet, it wrongly flagged 13 of 1,600 and missed 15 of 400.

---

## 13. Section IV-D: figures (replace all five)

Use the PNGs in `results/`. New captions:

- **Figure 1** (`fig1_accuracy_f1.png`): Accuracy and F1 for all five models on both datasets
  (seed 42).
- **Figure 2** (`fig2_error_rates.png`): False positive rate (legitimate users flagged) and
  false negative rate (attacks missed). Random Walk never raises a false alarm but misses many
  attacks. The rate threshold misses over half of them.
- **Figure 3** (`fig3_pta_scores.png`): Stage 1 PTA scores on the test sets, with the learned θ.
  The legitimate and attack distributions overlap heavily between 0.75 and 1.0. The PTA score
  alone can't separate them, which is why Stage 2 exists. Below θ there are only legitimate
  sessions, so the fast path is safe.
- **Figure 4** (`fig4_latency.png`): Processing time per session.
  - The Stage 1 fast path takes 0.009–0.013 ms.
  - The full hybrid takes 0.12–0.15 ms.
  - Called one session at a time, as in a live server, the MLP takes 0.22–0.24 ms.
  - Batched over 2,000 sessions, the MLP takes 0.015 ms per session, but batching isn't possible
    when each session needs an immediate decision.

  These timings come from single-threaded Python on one laptop and vary by about 10% between
  runs.
- **Figure 5** (`fig5_decisions.png`): What the hybrid actually decided on 2,000 test sessions.
  On SDSC: 12.8% allowed at Stage 1, 67.3% allowed at Stage 2, 0% challenged, 19.9% blocked. On
  ClarkNet: 3.4%, 76.7%, 0% and 19.9%.

---

## 14. Table 4: capability comparison

**Problems:**
- "Low false positives: No" for Random Walk is contradicted by its measured 0.0% FPR.
- "Catches slow mimicry bots: No" for PTA Only is partly wrong: it catches the ones with unusual
  navigation.

**Corrected rows:**

| Capability                | Ours          | PTA Only | Random Walk | MLP  | Rate Threshold |
|---------------------------|---------------|----------|-------------|------|----------------|
| Catches fast bots         | Yes           | Yes      | Partly      | Yes  | Yes            |
| Catches human-paced bots  | Yes           | Partly   | Partly      | Yes  | No             |
| Graded response           | Yes (rarely used, see §V-C) | No | No | No | No            |
| Explainable decisions     | Full          | Partial  | Partial     | No   | Full           |
| Low false positives       | Yes           | No       | Yes         | Yes  | Yes            |
| Low missed attacks        | Yes           | No       | No          | Partly | No           |

---

## 15. Section IV-E (new): corrections to the earlier draft

**Add this subsection:**

> **E. Corrections to the earlier draft.** An earlier version of this paper reported 100%
> accuracy and 0.0% FPR. After auditing that evaluation, we found three problems:
> 1. **Attack timing alone separated the classes.** A one-line rate threshold also scored 100%,
>    so the benchmark couldn't tell detectors apart.
> 2. **The PTA was never learned for the benchmark sites.** Every transition was unknown, so PTA
>    Only and Random Walk flagged every session (19% accuracy). That reflected our setup, not
>    those methods.
> 3. **The fixed θ = 0.60 was below even normal users' scores,** so Stage 1 never cleared a
>    session.
>
> We added human-paced bots, fast legitimate users and realistic navigation flows to the data,
> learned the PTA and θ from the training split, and tuned all baselines on the same split. The
> results above come from this corrected setup.

---

## 16. Section V-A: what the results mean

**Replace the whole subsection with:**

> The hybrid wins because it combines two kinds of evidence that each catch a different attack:
> - **Behavioural statistics** (rate, timing variance, repetition) catch floods.
> - **The PTA's page-order evidence** catches human-paced bots that take unusual paths. The
>   single most important rule in the trained tree is "the session contains a transition real
>   users almost never make".
>
> Each baseline sees only one kind of evidence and misses the other kind of attack.
>
> These results come from synthetic data, and the margins depend on how we generated it. They
> show that the design works under the conditions we modelled, not how it would perform on real
> traffic.

---

## 17. Section V-B: advantage over deep learning

**Problems:**
- The 0.006 ms figure and the "seven times faster" claim were never measured.
- The "80% of traffic" claim is wrong (see section 5 of this file).
- "Both achieve 100%" is no longer true.

**Replace "Both our system and the deep learning MLP achieve 100% accuracy, so why prefer
ours?" with:**

> Our system outperformed the MLP on both datasets (99.7% vs 95.4% and 98.4% vs 97.6% accuracy).
> The MLP had fewer false positives on ClarkNet. Beyond accuracy, there are three reasons to
> prefer the hybrid.

**Replace the "Second, efficiency" paragraph with:**

> Second, per-session cost. Evaluated one session at a time, as a live server must, the full
> hybrid took 0.12–0.15 ms per session against 0.22–0.24 ms for the MLP. Sessions cleared at
> Stage 1 took only about 0.01 ms. In our benchmark Stage 1 cleared 3–13% of sessions, because θ
> is set conservatively so that it never lets an attack through.

---

## 18. Section V-C: limitations

**Problems:**
- The paragraph about the manually set θ is now outdated, since θ is learned.
- The fact that CHALLENGE never fired needs to be stated.

**Replace the second paragraph with:**

> θ is now learned as the lowest attack score seen in training. This guarantees that no
> training attack is fast-pathed, but it clears only 3–13% of traffic. A higher θ would clear
> more, at the risk of letting attacks through. Choosing that trade-off on real traffic is
> future work.

**Add a new paragraph:**

> **The graded response is rarely exercised.** On these datasets the tree is confident: almost
> all of its leaves contain only one class, so attack probabilities are 0% or 100%, and CHALLENGE
> (35–70%) was triggered for 0 of 2,000 test sessions. Requiring at least 10–25 sessions per leaf
> produced only 4–11 challenges per 2,000 sessions. The mechanism works, but these datasets
> contain few genuinely ambiguous sessions. Real traffic, and calibrated probabilities, are
> needed to evaluate it properly.

---

## 19. Section VI: conclusion

**Problem:** the conclusion claims the system "simultaneously achieves 100% detection accuracy,
0.0% false positive rate…".

**Replace that sentence with:**

> In our evaluation, the system had the highest accuracy and lowest miss rate of the five
> approaches compared on both datasets, while keeping decisions traceable to readable rules.

**In Future Work, change the "Adaptive threshold" bullet to:**

> • Threshold trade-off: θ is now learned from training data. The next step is to choose it to
> balance fast-path coverage against missed attacks on real traffic.

**Add a bullet:**

> • Probability calibration: calibrate the tree's outputs so the CHALLENGE band reflects
> genuinely uncertain sessions.
