from pta.pta_model     import PTAModel
from pta.scoring       import session_pta_score
from pta.train_model   import MLModel
from pta.simulate_data import create_dataset

PTA_SUSPICION_THRESHOLD = 0.60
ML_LOW_RISK_THRESHOLD   = 0.35
ML_HIGH_RISK_THRESHOLD  = 0.70

class HybridDetector:
    def __init__(self):
        self.pta = PTAModel()
        self.ml  = MLModel()
        self.pta_threshold = PTA_SUSPICION_THRESHOLD
        self._build_pta()

    def _build_pta(self):
        transitions = [
            ("login",     "dashboard",    0.90, 2.0, 0.80, 1),
            ("dashboard", "profile",      0.50, 3.0, 1.00, 2),
            ("dashboard", "search",       0.40, 2.5, 0.90, 2),
            ("dashboard", "logout",       0.30, 1.5, 0.60, 1),
            ("profile",   "logout",       0.70, 2.0, 0.70, 1),
            ("profile",   "dashboard",    0.30, 2.5, 0.80, 1),
            ("search",    "dashboard",    0.60, 2.0, 0.80, 2),
            ("search",    "logout",       0.30, 1.5, 0.50, 1),
        ]
        for src, dst, prob, mu, sigma, wl in transitions:
            self.pta.add_transition(src, dst, prob, mu, sigma, wl)

    def train(self, n_samples=200):
        sessions, labels = create_dataset(n=n_samples)
        # The simulated set is small and artificial: with PTA features the tree
        # overfits generator quirks (e.g. lets an obvious flood through)
        self.fit(sessions, labels, pta_features=False)
        print(f"[TRAIN] PTA + Decision Tree fitted on {len(sessions)} sessions "
              f"({labels.count(0)} legitimate, {labels.count(1)} attack).")

    def fit(self, sessions, labels, pta_features=True):
        """Fit to a labelled dataset: learn the PTA from its legitimate
        sessions, train the Decision Tree (optionally with PTA features
        added), and set the Stage 1 threshold so only sessions scoring below
        every training attack are cleared."""
        self.pta.learn(sessions, labels)
        # Stage 2 also sees the PTA's view of the session
        self.ml.pta = self.pta if pta_features else None
        self.ml.train(sessions, labels)
        attack_scores = [self._stage1_pta_score(s)
                         for s, y in zip(sessions, labels) if y == 1]
        if attack_scores:
            self.pta_threshold = min(attack_scores)

    def _stage1_pta_score(self, session):
        return session_pta_score(self.pta, session)

    def _stage2_ml_risk(self, session):
        return self.ml.predict_proba(session)

    @staticmethod
    def _graded_response(attack_prob):
        if attack_prob < ML_LOW_RISK_THRESHOLD:
            return {"decision": "ALLOW",     "risk": "LOW"}
        elif attack_prob < ML_HIGH_RISK_THRESHOLD:
            return {"decision": "CHALLENGE", "risk": "MEDIUM"}
        else:
            return {"decision": "BLOCK",     "risk": "HIGH"}

    def evaluate_session(self, session):
        pta_score = self._stage1_pta_score(session)
        if pta_score < self.pta_threshold:
            return {"pta_score": round(pta_score,4), "stage": "PTA",
                    "decision": "ALLOW", "risk": "LOW", "attack_prob": None}
        attack_prob = self._stage2_ml_risk(session)
        result = self._graded_response(attack_prob)
        return {"pta_score": round(pta_score,4), "stage": "ML",
                "decision": result["decision"], "risk": result["risk"],
                "attack_prob": round(attack_prob,4)}

    def explain(self):
        """The trained Decision Tree as readable if/then rules."""
        from sklearn.tree import export_text
        names = self.ml.FEATURE_NAMES + (self.ml.PTA_FEATURE_NAMES
                                         if self.ml.pta is not None else [])
        return export_text(self.ml.model, feature_names=names,
                           show_weights=True)

    def evaluate_batch(self, sessions):
        return [self.evaluate_session(s) for s in sessions]
