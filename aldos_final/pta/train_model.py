import numpy as np
from sklearn.model_selection import GridSearchCV
from sklearn.tree import DecisionTreeClassifier
from pta.scoring import session_pta_score, min_transition_prob

# Candidate tree sizes, chosen per dataset by cross-validation on the
# training data only. min_samples_leaf: no rule may rest on a handful of
# training sessions.
TREE_GRID = {"max_depth": [4, 5, 6, 7], "min_samples_leaf": [10, 20, 40]}

FEATURE_NAMES = ["request_rate","think_time_variance",
                 "page_repetition","session_duration","rapid_requests",
                 "longest_rapid_streak","longest_same_page_streak",
                 "cost_rate","median_think_time","think_time_cv"]

def _longest_streak(flags):
    best = run = 0
    for f in flags:
        run  = run + 1 if f else 0
        best = max(best, run)
    return best

def behaviour_features(session, page_cost=None):
    """Session statistics shared by the Decision Tree and the MLP baseline.
    The two streak features can't be diluted by prepending decoy pages.
    cost_rate is server cost per second (page_cost, default 1 per request);
    think_time_cv is timing regularity: bots are steadier than humans."""
    if not session:
        return [0.0] * len(FEATURE_NAMES)
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
    cost            = sum((page_cost or {}).get(p, 1.0) for p in pages)
    cost_rate       = cost / (session_duration + 1e-6)
    median_think    = float(np.median(times))
    think_cv        = float(np.std(times) / (np.mean(times) + 1e-6))
    return [round(request_rate,6), round(think_time_variance,6),
            round(page_repetition,6), round(session_duration,6), rapid_requests,
            rapid_streak, same_streak,
            round(cost_rate,6), round(median_think,6), round(think_cv,6)]

class MLModel:
    FEATURE_NAMES     = FEATURE_NAMES
    PTA_FEATURE_NAMES = ["pta_score","min_transition_prob"]

    def __init__(self, max_depth=5, min_samples_leaf=20, pta=None, page_cost=None,
                 tune=True):
        self.model = DecisionTreeClassifier(max_depth=max_depth,
                                            min_samples_leaf=min_samples_leaf,
                                            random_state=42)
        self.pta       = pta         # when set, PTA features are appended
        self.page_cost = page_cost
        self.tune      = tune        # pick depth/leaf size by 3-fold CV (F1)
        self.params    = {"max_depth": max_depth, "min_samples_leaf": min_samples_leaf}

    def extract_features(self, session):
        base = behaviour_features(session, self.page_cost)
        if self.pta is not None:
            base += [round(session_pta_score(self.pta, session), 6),
                     round(min_transition_prob(self.pta, session), 6)]
        return base

    def train(self, sessions, labels):
        X = [self.extract_features(s) for s in sessions]
        if self.tune:
            search = GridSearchCV(DecisionTreeClassifier(random_state=42),
                                  TREE_GRID, scoring="f1", cv=3)
            search.fit(X, labels)
            self.model, self.params = search.best_estimator_, search.best_params_
        else:
            self.model.fit(X, labels)

    def predict_proba(self, session):
        X = [self.extract_features(session)]
        proba = self.model.predict_proba(X)[0]
        classes = list(self.model.classes_)
        return float(proba[classes.index(1)]) if 1 in classes else 0.0

    def predict(self, session):
        return int(self.model.predict([self.extract_features(session)])[0])
