import numpy as np
from sklearn.tree import DecisionTreeClassifier
from pta.scoring import session_pta_score, min_transition_prob

FEATURE_NAMES = ["request_rate","think_time_variance",
                 "page_repetition","session_duration","rapid_requests",
                 "longest_rapid_streak","longest_same_page_streak"]

def _longest_streak(flags):
    best = run = 0
    for f in flags:
        run  = run + 1 if f else 0
        best = max(best, run)
    return best

def behaviour_features(session):
    """Session statistics shared by the Decision Tree and the MLP baseline.
    The two streak features can't be diluted by prepending decoy pages."""
    if not session:
        return [0.0, 0.0, 0.0, 0.0, 0, 0, 0]
    times = [t for _, t in session]
    pages = [p for p, _ in session]
    session_duration    = sum(times)
    request_rate        = len(session) / (session_duration + 1e-6)
    think_time_variance = float(np.var(times)) if len(times) > 1 else 0.0
    page_counts = {}
    for pg in pages:
        page_counts[pg] = page_counts.get(pg, 0) + 1
    page_repetition = max(page_counts.values()) / len(pages)
    rapid_requests  = sum(1 for t in times if t < 0.5)
    rapid_streak    = _longest_streak(t < 0.5 for t in times)
    # +1: a run of k identical transitions covers k+1 requests to the page
    same_streak     = _longest_streak(pages[i] == pages[i - 1]
                                      for i in range(1, len(pages))) + 1
    return [round(request_rate,6), round(think_time_variance,6),
            round(page_repetition,6), round(session_duration,6), rapid_requests,
            rapid_streak, same_streak]

class MLModel:
    FEATURE_NAMES     = FEATURE_NAMES
    PTA_FEATURE_NAMES = ["pta_score","min_transition_prob"]

    def __init__(self, max_depth=5, pta=None):
        self.model = DecisionTreeClassifier(max_depth=max_depth, random_state=42)
        self.pta   = pta   # when set, PTA features are appended

    def extract_features(self, session):
        base = behaviour_features(session)
        if self.pta is not None:
            base += [round(session_pta_score(self.pta, session), 6),
                     round(min_transition_prob(self.pta, session), 6)]
        return base

    def train(self, sessions, labels):
        X = [self.extract_features(s) for s in sessions]
        self.model.fit(X, labels)

    def predict_proba(self, session):
        X = [self.extract_features(session)]
        proba = self.model.predict_proba(X)[0]
        classes = list(self.model.classes_)
        return float(proba[classes.index(1)]) if 1 in classes else 0.0

    def predict(self, session):
        return int(self.model.predict([self.extract_features(session)])[0])
