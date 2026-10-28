import numpy as np

def compute_pthink(t, mu, sigma):
    if sigma == 0:
        return 1.0 if t == mu else 0.1
    return float(np.exp(-abs(t - mu) / (sigma + 1e-6)))

def suspicion_score(edge, think_time):
    p_trans  = edge["prob"]
    mu       = edge["mean_time"]
    sigma    = edge["std_time"]
    workload = edge.get("workload", 1.0)
    p_think  = compute_pthink(think_time, mu, sigma)
    return workload * (1.0 - p_trans * p_think)

def session_pta_score(pta, session):
    """Mean suspicion over a session's transitions; unknown transitions score 1.0."""
    scores = []
    for i in range(len(session) - 1):
        src, _       = session[i]
        dst, think_t = session[i + 1]
        edge = pta.get_transition(src, dst)
        scores.append(1.0 if edge is None else suspicion_score(edge, think_t))
    return float(np.mean(scores)) if scores else 0.0

def min_transition_prob(pta, session):
    """Probability of the session's least likely transition (0 if unknown)."""
    probs = [1.0]
    for i in range(len(session) - 1):
        edge = pta.get_transition(session[i][0], session[i + 1][0])
        probs.append(0.0 if edge is None else edge["prob"])
    return min(probs)
