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
> and ClarkNet-HTTP logs used in the original paper. The datasets include human-paced bots,
> attacks disguised behind normal-looking requests, and fast legitimate users, so that no single
> signal separates the classes. We compared the system against four other approaches, including a
> deep-learning neural network. Averaged over five random seeds, our system achieved 99.8% and
> 99.7% accuracy and missed about 1% of attacks, against 10–77% for the other approaches. Every
> decision traces back to readable rules.

---

## 2. Section I: Introduction, contributions list

**Problem:** the third bullet says "five other models".

**Change it to:**

> • A comparison against four other approaches (the original PTA, a Random Walk model, a
> deep-learning MLP and a rate threshold) on 10,000-session datasets, reported as the mean over
> five random seeds.

**Add a fifth bullet:**

> • An adversarial evaluation of our own detector. It found an evasion (a decoy prefix of normal
> browsing), which we closed with two streak features that a decoy can't dilute.

---

## 3. Section II-D: Random Walk

**Problem:** the paper says Random Walk "blocks far too many legitimate users". In our own
benchmark it had **0.0% FPR**. Its weakness was missed attacks (FNR 13.4% and 38.3%). Our
legitimate users don't include deep-link visitors arriving from search engines, so we can't
support the false-positive claim with data.

**Replace the last two sentences with:**

> The original authors note that legitimate users who enter deep pages directly (for example
> from a search engine) can look like deviations. In our benchmark, Random Walk raised no false
> alarms, but because it ignores timing it missed every bot whose navigation looked normal:
> 13.4% of attacks on SDSC and 38.3% on ClarkNet.

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
> per page transition, measured at about 0.009 ms per session.
>
> Instead of a fixed threshold, θ is learned from the training data. It is set to the lowest
> score of any attack session in the training set, so Stage 1 only fast-paths sessions that look
> more normal than every attack seen in training. This makes Stage 1 deliberately conservative:
> - On the SDSC test set (θ = 0.608) it cleared 6.3% of all sessions (7.9% of legitimate users).
> - On ClarkNet (θ = 0.724) it cleared 5.6% (7.1% of legitimate users).
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

**Problem:** the paper describes five features. The tree now uses nine.

**Add after the five feature bullets:**

> • **Longest rapid streak:** the longest run of consecutive requests under 0.5 s.
> • **Longest same-page streak:** the longest run of consecutive requests to one page.
>
> We added these two streak features after testing our own detector against evasion (Section
> IV-F). Whole-session statistics such as page repetition can be diluted by opening with a few
> normal-looking requests. A decoy prefix can't shorten a streak.
>
> Stage 2 also gets two features from the PTA, so the page-order evidence from Stage 1 isn't
> thrown away:
> - **PTA score:** the Stage 1 suspicion score.
> - **Minimum transition probability:** how likely the least likely step in the session is
>   (0 if real users never take it).

**Update the code block** so `extract_features` also returns `rapid_streak` and
`same_page_streak`.

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

> The tree trained on SDSC-HTTP has depth 5 and 12 leaves. Its main rules:
>
> ```
> Is min_transition_prob ≤ 0.02?             (a step real users almost never take)
>   YES → ATTACK                              0 legit / 1,379 attack
>   NO  → Is longest_same_page_streak ≤ 4.5?
>          YES → Is longest_rapid_streak ≤ 3.5?
>                 YES → LEGITIMATE            6,393 legit / 13 attack
>                 NO  → Is request_rate > 1.39 and pta_score > 0.80?
>                        YES → ATTACK         0 legit / 12 attack
>          NO  → Is request_rate > 0.43?
>                 YES → ATTACK                0 legit / 193 attack
> ```
>
> The first rule alone catches 1,379 of the 1,600 training attacks. Every one of them contained
> a page transition that legitimate users essentially never make. The streak rules catch floods
> and repeated-page bots, including those hidden behind a decoy.

---

## 9. Section III-D: Dataset setup

**Problems:**
- The page distributions describe the old generator, where legitimate users picked pages at
  random. They now follow navigation flows.
- The "grey-area sessions" paragraph describes `simulate_data.py`, which no longer drives any
  reported result.
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
> To prevent any single signal from separating the classes:
> - Each attack session gets one pacing:
>   - 40% flood (0.05–0.20 s between requests).
>   - 30% are slow bots (0.3–1.1 s).
>   - 30% are paced like humans (about 1.7 s) but more regular than real users.
> - 30% of attack sessions open with 1–3 normal-looking requests (a decoy).
>
> **Split and seeds.** Each dataset has 10,000 sessions (80% legitimate, 20% attack): 8,000 for
> training and 2,000 for testing. The PTA is learned only from legitimate training sessions. All
> results are the mean ± standard deviation over five random seeds (42, 1, 2, 3, 4), except the
> confusion matrix, Table 1 and figures, which use seed 42.
>
> **Baseline tuning.** The PTA Only and Random Walk thresholds are tuned on the same training
> split, using the same learned PTA, and the MLP gets the same behavioural features as our tree,
> so all models are compared on equal terms.

---

## 10. Section IV-A: Table 1 and its text

**Problem:** the old table comes from a hand-written graph and toy data. It also uses pages
(login, dashboard) that don't exist in the benchmark.

**Replace the paragraph and Table 1 with** (from `python main.py`, which uses the detector
trained on SDSC-HTTP):

> Table 1 shows how the detector trained on SDSC-HTTP handles eight example sessions.
>
> - **The most important row is the fast legitimate user,** who clicks every 0.7–1.2 s. Their
>   PTA score is 0.720, so a fixed-threshold system (θ = 0.60) would block them. Our system sends
>   them to Stage 2, which gives a 0.1% attack probability and allows them through.
> - **The slow checkout bot is caught.** It paces itself like a human (about 1.8 s), but repeats
>   a transition that real users never make.
> - **The disguised flood is caught too.** It opens with three normal pages before flooding, but
>   that doesn't affect the streak features.

| Session              | Pages                                   | PTA score | Stage | Decision | Attack prob. |
|----------------------|-----------------------------------------|----------:|-------|----------|-------------:|
| Normal shopper       | index→search→product→cart→checkout→logout (1.5–5.2 s) | 0.690 | ML | ALLOW | 0.1% |
| Checkout flood       | checkout ×6 (0.1 s)                      | 1.000     | ML    | BLOCK    | 100%         |
| Slow checkout bot    | checkout ×5 (~1.8 s)                     | 1.000     | ML    | BLOCK    | 100%         |
| Fast legitimate user | index→search→product→cart→checkout (0.7–1.2 s) | 0.720 | ML | ALLOW | 0.1% |
| Medium-risk bot      | search×2→product→search→logout (0.2–0.8 s) | 0.872   | ML    | BLOCK    | 100%         |
| Product browser      | index→product×3→search (2.0–4.1 s)       | 0.798     | ML    | ALLOW    | 0.1%         |
| Disguised flood      | index→search→product, then product ×6 (0.1 s) | 0.843 | ML | BLOCK  | 100%         |
| Hand-crafted attack  | login×2→search×2 (0.07–0.09 s)           | 0.941     | ML    | BLOCK    | 100%         |

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
>   about 64% of attacks (human-paced bots and floods hidden behind a decoy). Random Walk sees
>   only page order, so it never raises a false alarm but misses bots whose navigation looks
>   normal.
> - **The hybrid wins by combining both kinds of evidence.** Behavioural statistics and the
>   PTA's page-order evidence go into the same classifier.
> - **Its false-positive rate is 0.0% on SDSC and 0.2% on ClarkNet,** second only to Random Walk.

**Table 2a: SDSC-HTTP (mean ± std, 5 seeds)**

| Model                 | Accuracy    | F1          | FPR        | FNR         |
|-----------------------|-------------|-------------|------------|-------------|
| **Hybrid PTA+DT (ours)** | **99.8 ± 0.1** | **99.5 ± 0.2** | **0.0 ± 0.0** | **0.9 ± 0.5** |
| PTA Only [1]          | 92.1 ± 0.3  | 80.6 ± 1.3  | 5.8 ± 0.5  | 16.7 ± 3.5  |
| Random Walk [9]       | 97.4 ± 0.2  | 92.8 ± 0.6  | **0.0 ± 0.0** | 13.4 ± 1.1 |
| Deep Learning MLP     | 96.0 ± 0.1  | 89.4 ± 0.5  | 1.2 ± 0.1  | 15.2 ± 0.9  |
| Rate Threshold        | 86.4 ± 0.1  | 50.8 ± 0.9  | 1.1 ± 0.1  | 64.4 ± 1.0  |

**Table 2b: ClarkNet-HTTP (mean ± std, 5 seeds)**

| Model                 | Accuracy    | F1          | FPR        | FNR         |
|-----------------------|-------------|-------------|------------|-------------|
| **Hybrid PTA+DT (ours)** | **99.7 ± 0.1** | **99.1 ± 0.3** | 0.2 ± 0.1 | **1.1 ± 0.5** |
| PTA Only [1]          | 82.3 ± 0.9  | 34.3 ± 1.9  | 2.5 ± 0.4  | 77.2 ± 1.6  |
| Random Walk [9]       | 92.2 ± 1.0  | 76.2 ± 2.9  | **0.0 ± 0.0** | 38.3 ± 3.8 |
| Deep Learning MLP     | 97.2 ± 0.4  | 92.9 ± 1.0  | 0.7 ± 0.2  | 10.9 ± 1.9  |
| Rate Threshold        | 85.5 ± 0.5  | 49.8 ± 2.2  | 1.6 ± 0.3  | 64.7 ± 2.2  |

---

## 12. Section IV-C: confusion matrix

**Replace Table 3 and the sentence after it** (seed 42; CHALLENGE and BLOCK both count as
"predicted attack"):

|                    | Predicted legitimate | Predicted attack |
|--------------------|---------------------:|-----------------:|
| **SDSC: actual legitimate**     | 1,599 | 1   |
| **SDSC: actual attack**         | 1     | 399 |
| **ClarkNet: actual legitimate** | 1,567 | 4   |
| **ClarkNet: actual attack**     | 4     | 425 |

> On SDSC, the hybrid wrongly flagged 1 of 1,600 legitimate users and missed 1 of 400 attacks.
> On ClarkNet, it wrongly flagged 4 of 1,571 and missed 4 of 429.

---

## 13. Section IV-D: figures (replace all five)

Use the PNGs in `results/`. New captions:

- **Figure 1** (`fig1_accuracy_f1.png`): Accuracy and F1 for all five models on both datasets
  (seed 42).
- **Figure 2** (`fig2_error_rates.png`): False positive rate (legitimate users flagged) and
  false negative rate (attacks missed). Random Walk never raises a false alarm but misses many
  attacks. The rate threshold misses about two-thirds of them.
- **Figure 3** (`fig3_pta_scores.png`): Stage 1 PTA scores on the test sets, with the learned θ.
  The legitimate and attack distributions overlap heavily above θ. The PTA score alone can't
  separate them, which is why Stage 2 exists. Below θ there are only legitimate sessions, so the
  fast path is safe.
- **Figure 4** (`fig4_latency.png`): Processing time per session.
  - The Stage 1 fast path takes about 0.009 ms.
  - The full hybrid takes about 0.12 ms.
  - Called one session at a time, as in a live server, the MLP takes about 0.22 ms.
  - Batched over 2,000 sessions, the MLP takes 0.02–0.04 ms per session, but batching isn't
    possible when each session needs an immediate decision.

  These timings come from single-threaded Python on one laptop and vary by about 10% between
  runs.
- **Figure 5** (`fig5_decisions.png`): What the hybrid actually decided on 2,000 test sessions.
  - SDSC: 6.3% allowed at Stage 1, 73.7% allowed at Stage 2, 1 session (0.05%) challenged,
    20.0% blocked.
  - ClarkNet: 5.6%, 73.0%, 4 sessions (0.2%) and 21.3%.

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
| Catches human-paced bots  | Yes           | Partly   | Partly      | Partly | No           |
| Catches decoy-prefixed floods | Yes       | Partly   | Partly      | Partly | No           |
| Graded response           | Yes (rarely triggered, see §V-C) | No | No | No | No          |
| Explainable decisions     | Full          | Partial  | Partial     | No   | Full           |
| Low false positives       | Yes           | No       | Yes         | Yes  | Yes            |
| Low missed attacks        | Yes           | No       | No          | No   | No             |

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

## 16. Section IV-F (new): adversarial evaluation

**Add this subsection:**

> **F. Evading our own detector.** After the corrections above, we tried to evade the detector
> by hand. One normal page followed by six product requests 0.1 s apart was allowed with 0%
> attack probability:
> - Every flood in the training data hit a single page from start to finish, so the tree had
>   learned "almost all requests go to one page" as the flood signal.
> - A single decoy page lowered that share below the tree's cut-off.
>
> We closed the gap in two ways:
> - Decoy-prefixed attacks (30% of attacks) were added to the data.
> - Two streak features (the longest run of rapid requests and of same-page requests) were added
>   to the classifier. A decoy can't dilute either of them.
>
> After retraining, the detector blocks all of the following:
> - floods behind decoys of one to five pages
> - floods followed by a decoy suffix
> - floods alternating between two pages
> - floods paced at 0.6 s, just above the "rapid" cut-off
> - human-paced single-page bots
>
> It still allows a three-request session with two fast clicks, which we consider too short to
> judge. A real user double-clicking looks the same.
>
> This exercise shows a general limitation of supervised detection: the model catches the
> evasions it was trained on, and new strategies may require new data or features.

---

## 17. Section V-A: what the results mean

**Replace the whole subsection with:**

> The hybrid wins because it combines two kinds of evidence that each catch a different attack:
> - **Behavioural statistics** (rate, timing variance, repetition and streaks) catch floods,
>   including disguised ones.
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

## 18. Section V-B: advantage over deep learning

**Problems:**
- The 0.006 ms figure and the "seven times faster" claim were never measured.
- The "80% of traffic" claim is wrong (see section 5 of this file).
- "Both achieve 100%" is no longer true.

**Replace "Both our system and the deep learning MLP achieve 100% accuracy, so why prefer
ours?" with:**

> Our system outperformed the MLP on both datasets, even though the MLP received the same
> behavioural features:
> - Accuracy: 99.8% vs 96.0% (SDSC) and 99.7% vs 97.2% (ClarkNet).
> - Missed attacks: about 1% vs 11–15%.
>
> The main reason is that our tree also receives the PTA's page-order evidence. Beyond accuracy,
> there are three reasons to prefer the hybrid.

**Replace the "Second, efficiency" paragraph with:**

> Second, per-session cost. Evaluated one session at a time, as a live server must, the full
> hybrid took about 0.12 ms per session against 0.22 ms for the MLP. Sessions cleared at Stage 1
> took only about 0.009 ms. In our benchmark Stage 1 cleared about 6% of sessions, because θ is
> set conservatively so that it never lets a training attack through.

---

## 19. Section V-C: limitations

**Problems:**
- The paragraph about the manually set θ is now outdated, since θ is learned.
- It needs to say how rarely CHALLENGE fired.

**Replace the second paragraph with:**

> θ is now learned as the lowest attack score seen in training. This guarantees that no
> training attack is fast-pathed, but it clears only about 6% of traffic. A higher θ would clear
> more, at the risk of letting attacks through. Choosing that trade-off on real traffic is
> future work.

**Add these paragraphs:**

> **The graded response is rarely exercised.** On these datasets the tree is confident: almost
> all of its leaves contain only one class, so attack probabilities are nearly always 0% or
> 100%. CHALLENGE (35–70%) was triggered for 1 of 2,000 SDSC test sessions and 4 of 2,000
> ClarkNet sessions. The mechanism works (the demo shows a legitimate user receiving a CHALLENGE
> at 44% instead of being blocked), but these datasets contain few genuinely ambiguous sessions.
>
> **Adversarial robustness was tested by hand** against the evasion strategies we thought of
> (Section IV-F). Attackers may find others.

---

## 20. Section VI: conclusion

**Problem:** the conclusion claims the system "simultaneously achieves 100% detection accuracy,
0.0% false positive rate…".

**Replace that sentence with:**

> In our evaluation, the system had the highest accuracy and lowest miss rate of the five
> approaches compared on both datasets, including after we tried to evade it, while keeping
> decisions traceable to readable rules.

**In Future Work, change the "Adaptive threshold" bullet to:**

> • Threshold trade-off: θ is now learned from training data. The next step is to choose it to
> balance fast-path coverage against missed attacks on real traffic.

**Add these bullets:**

> • Probability calibration: calibrate the tree's outputs so the CHALLENGE band reflects
> genuinely uncertain sessions.
>
> • Systematic adversarial testing: generate evasion strategies automatically rather than by
> hand.
