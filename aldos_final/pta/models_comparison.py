"""
models_comparison.py
====================
Five models benchmarked on SDSC-HTTP and CLARKNET-HTTP style datasets.

  1. Hybrid PTA + DT  (Ours)           — two-stage with graded response
  2. PTA Only         (Praseed 2021)    — original binary decision
  3. Random Walk      (Xu et al. 2014) — flags first deviation
  4. Deep Learning    (MLP)            — multi-layer neural network
  5. Rate Threshold                    — simple statistical baseline
"""

import numpy as np
import time
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, confusion_matrix)
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from pta.scoring import session_pta_score, min_transition_prob
from pta.train_model import behaviour_features


# ── Helper: the same behavioural features used by our ML stage ───────────────
def extract_features(session, page_cost=None):
    return behaviour_features(session, page_cost)


# ── Helper: pick the cut-off on a 1-D score that maximises training F1 ───────
# (F1, not accuracy: with 80% legitimate traffic, "never flag" scores 80%)
def best_threshold(scores, labels, attack_if_above=True):
    scores = np.asarray(scores, dtype=float)
    labels = np.asarray(labels)
    s = scores if attack_if_above else -scores        # flag when s >= cut-off
    cuts = np.unique(s)
    order = np.sort(s)
    pos = np.sort(s[labels == 1])
    flagged = len(s) - np.searchsorted(order, cuts, side="left")
    tp      = len(pos) - np.searchsorted(pos, cuts, side="left")
    f1      = 2 * tp / (flagged + len(pos) + 1e-12)
    best    = cuts[int(np.argmax(f1))]
    return float(best if attack_if_above else -best)


# ── Model 1: PTA Only ─────────────────────────────────────────────────────────
class PTAOnlyModel:
    """Original Praseed & Thilagam (2021) — binary block/allow."""
    name = "PTA Only (Praseed 2021)"

    def __init__(self, threshold=0.55):
        self.threshold = threshold
        self.pta = None

    def fit(self, pta_model, sessions=None, labels=None):
        self.pta = pta_model
        if sessions is not None and labels is not None:
            self.threshold = best_threshold(
                [self._score(s) for s in sessions], labels)

    def _score(self, session):
        return session_pta_score(self.pta, session)

    def predict(self, sessions):
        return [1 if self._score(s) >= self.threshold else 0 for s in sessions]


# ── Model 2: Random Walk ──────────────────────────────────────────────────────
class RandomWalkModel:
    """Xu et al. (2014) — flag at first unexpected transition."""
    name = "Random Walk (Xu et al. 2014)"

    def __init__(self, deviation_threshold=0.35):
        self.deviation_threshold = deviation_threshold
        self.pta = None

    def fit(self, pta_model, sessions=None, labels=None):
        self.pta = pta_model
        if sessions is not None and labels is not None:
            # flagged when the least likely transition falls below the cut-off
            t = best_threshold([self._min_prob(s) for s in sessions], labels,
                               attack_if_above=False)
            self.deviation_threshold = t + 1e-9

    def _min_prob(self, session):
        return min_transition_prob(self.pta, session)

    def predict(self, sessions):
        return [1 if self._min_prob(s) < self.deviation_threshold else 0
                for s in sessions]


# ── Model 3: Deep Learning (MLP Neural Network) ───────────────────────────────
class DeepLearningModel:
    """
    Multi-Layer Perceptron — represents modern deep learning approaches.
    3 hidden layers: 64 → 32 → 16 neurons, ReLU activation.
    Same behavioural features as our Decision Tree for a fair comparison.
    """
    name = "Deep Learning / MLP (Neural Net)"

    def __init__(self, page_cost=None):
        self.page_cost = page_cost
        self.model = MLPClassifier(
            hidden_layer_sizes=(64, 32, 16),
            activation='relu',
            max_iter=500,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.1,
        )
        self.scaler = StandardScaler()
        self.trained = False

    def fit(self, pta_model, sessions, labels):
        X = [extract_features(s, self.page_cost) for s in sessions]
        X = self.scaler.fit_transform(X)
        self.model.fit(X, labels)
        self.trained = True

    def predict(self, sessions):
        if not self.trained:
            return [0] * len(sessions)
        X = [extract_features(s, self.page_cost) for s in sessions]
        X = self.scaler.transform(X)
        return list(self.model.predict(X))

    def predict_proba(self, sessions):
        X = [extract_features(s, self.page_cost) for s in sessions]
        X = self.scaler.transform(X)
        return self.model.predict_proba(X)[:, 1]


# ── Model 4: Rate Threshold ───────────────────────────────────────────────────
class RateThresholdModel:
    """Traditional statistical baseline."""
    name = "Rate Threshold (Baseline)"

    def __init__(self, rate_threshold=1.8):
        self.rate_threshold = rate_threshold

    def fit(self, pta_model=None, sessions=None, labels=None):
        pass

    def predict(self, sessions):
        preds = []
        for session in sessions:
            times = [t for _, t in session]
            rate  = len(session) / (sum(times) + 1e-6)
            preds.append(1 if rate > self.rate_threshold else 0)
        return preds


# ── Metrics ───────────────────────────────────────────────────────────────────
def evaluate_model(name, y_true, y_pred, elapsed_ms):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn + 1e-9)
    fnr = fn / (fn + tp + 1e-9)
    return {
        "Model":      name,
        "Accuracy":   round(accuracy_score(y_true, y_pred) * 100, 1),
        "Precision":  round(precision_score(y_true, y_pred, zero_division=0) * 100, 1),
        "Recall":     round(recall_score(y_true, y_pred, zero_division=0) * 100, 1),
        "F1":         round(f1_score(y_true, y_pred, zero_division=0) * 100, 1),
        "FPR %":      round(fpr * 100, 2),
        "FNR %":      round(fnr * 100, 1),
        "ms/sess":    round(elapsed_ms, 3),
    }


# ── Main comparison runner ────────────────────────────────────────────────────
def run_comparison(detector, pta_model, train_sessions, train_labels,
                   test_sessions, test_labels):
    results = []

    # 1. Hybrid (Ours)
    t0 = time.perf_counter()
    hybrid_preds = [0 if detector.evaluate_session(s)["decision"] == "ALLOW"
                    else 1 for s in test_sessions]
    elapsed = (time.perf_counter() - t0) * 1000 / len(test_sessions)
    results.append(evaluate_model("Hybrid PTA+DT (Ours)",
                                  test_labels, hybrid_preds, elapsed))

    # 2. PTA Only
    m = PTAOnlyModel(threshold=0.55)
    m.fit(pta_model, train_sessions, train_labels)
    t0 = time.perf_counter()
    preds = m.predict(test_sessions)
    elapsed = (time.perf_counter() - t0) * 1000 / len(test_sessions)
    results.append(evaluate_model(m.name, test_labels, preds, elapsed))

    # 3. Random Walk
    m = RandomWalkModel(deviation_threshold=0.35)
    m.fit(pta_model, train_sessions, train_labels)
    t0 = time.perf_counter()
    preds = m.predict(test_sessions)
    elapsed = (time.perf_counter() - t0) * 1000 / len(test_sessions)
    results.append(evaluate_model(m.name, test_labels, preds, elapsed))

    # 4. Deep Learning MLP
    dl = DeepLearningModel(page_cost=detector.ml.page_cost)
    print("    [Training Deep Learning model...]")
    dl.fit(pta_model, train_sessions, train_labels)
    t0 = time.perf_counter()
    preds = dl.predict(test_sessions)
    elapsed = (time.perf_counter() - t0) * 1000 / len(test_sessions)
    results.append(evaluate_model(dl.name, test_labels, preds, elapsed))

    # 5. Rate Threshold
    m = RateThresholdModel(rate_threshold=1.8)
    t0 = time.perf_counter()
    preds = m.predict(test_sessions)
    elapsed = (time.perf_counter() - t0) * 1000 / len(test_sessions)
    results.append(evaluate_model(m.name, test_labels, preds, elapsed))

    return results


# ── Pretty printer ────────────────────────────────────────────────────────────
def print_comparison_table(results, dataset_name):
    cols = ["Accuracy", "Precision", "Recall", "F1", "FPR %", "FNR %", "ms/sess"]
    cw, nw = 30, 11

    print(f"\n{'='*105}")
    print(f"  COMPARISON RESULTS — {dataset_name}")
    print(f"{'='*105}")
    print(f"  {'Model':<{cw}}" + "".join(f"{c:>{nw}}" for c in cols))
    print(f"  {'─'*102}")

    for r in results:
        is_ours = "Ours" in r["Model"]
        marker  = "►" if is_ours else " "
        row     = f" {marker} {r['Model']:<{cw - 2}}"
        for c in cols:
            val = r[c]
            row += f"{val:>{nw}}"
        print(row)

    print(f"  {'─'*102}")
    print(f"  ► = Our hybrid system\n")

    # winner summary
    best_acc = max(results, key=lambda r: r["Accuracy"])
    best_f1  = max(results, key=lambda r: r["F1"])
    best_fpr = min(results, key=lambda r: r["FPR %"])
    print(f"  Best Accuracy  : {best_acc['Model']} ({best_acc['Accuracy']}%)")
    print(f"  Best F1 Score  : {best_f1['Model']} ({best_f1['F1']}%)")
    print(f"  Lowest FPR     : {best_fpr['Model']} ({best_fpr['FPR %']}%)\n")
