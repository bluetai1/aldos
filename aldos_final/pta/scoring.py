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

def _known_transitions(pta, session):
    """Transitions between pages the PTA has seen. Steps involving a page
    absent from training (e.g. one added to the site since) are skipped:
    they are unknown, not evidence of an attack."""
    for i in range(len(session) - 1):
        (src, _), (dst, think_t) = session[i], session[i + 1]
        if pta.knows(src) and pta.knows(dst):
            yield src, dst, think_t

def known_transition_count(pta, session):
    return sum(1 for _ in _known_transitions(pta, session))

def session_pta_score(pta, session):
    """Mean suspicion over a session's transitions. An unseen transition
    between known pages scores the maximum, scaled by the page's workload."""
    scores = []
    for src, dst, think_t in _known_transitions(pta, session):
        edge = pta.get_transition(src, dst)
        scores.append(pta.page_workload.get(dst, 1.0) if edge is None
                      else suspicion_score(edge, think_t))
    return float(np.mean(scores)) if scores else 0.0

def min_transition_prob(pta, session):
    """Probability of the session's least likely transition between known
    pages (0 if never seen)."""
    probs = [1.0]
    for src, dst, _ in _known_transitions(pta, session):
        edge = pta.get_transition(src, dst)
        probs.append(0.0 if edge is None else edge["prob"])
    return min(probs)
