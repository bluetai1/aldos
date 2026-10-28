import numpy as np
from sklearn.tree import DecisionTreeClassifier
from pta.scoring import session_pta_score, min_transition_prob

class MLModel:
    FEATURE_NAMES = ["request_rate","think_time_variance",
                     "page_repetition","session_duration","rapid_requests"]
    PTA_FEATURE_NAMES = ["pta_score","min_transition_prob"]

    def __init__(self, max_depth=5, pta=None):
        self.model = DecisionTreeClassifier(max_depth=max_depth, random_state=42)
        self.pta   = pta   # when set, PTA features are appended

    def extract_features(self, session):
        base = self._behaviour_features(session)
        if self.pta is not None:
            base += [round(session_pta_score(self.pta, session), 6),
                     round(min_transition_prob(self.pta, session), 6)]
        return base

    def _behaviour_features(self, session):
        if not session:
            return [0.0, 0.0, 0.0, 0.0, 0]
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
        return [round(request_rate,6), round(think_time_variance,6),
                round(page_repetition,6), round(session_duration,6), rapid_requests]

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
