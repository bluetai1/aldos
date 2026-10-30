"""
datasets.py
===========
Reconstructs SDSC-HTTP and CLARKNET-HTTP style sessions based on the
statistical properties reported in Praseed & Thilagam (IEEE TIFS 2021).

SDSC-HTTP  : ~30,000 requests, 1 day of logs, SDSC WWW server
CLARKNET   : ~1,300,000 requests, 2 weeks, ClarkNet WWW server

We reproduce:
 - Realistic URL distributions (login/index heavy, search/profile lighter)
 - Think time distributions matching real web logs (log-normal, mean ~2s)
 - Session groupings with realistic session lengths
 - Attack injection following the paper's methodology (Section IV-A)

To keep the benchmark from being trivially separable:
 - Legitimate users follow a navigation flow (Markov chain), not random pages
 - ~20% of legitimate users are fast "power users" (~1s think times)
 - Only ~40% of attacks flood; the rest pace requests to look human
 - ~30% of attacks open with a few normal-looking requests (decoy prefix)
 - A6 bots follow the legitimate navigation flow with machine-regular timing

Page costs (*_COST) are assumed relative server costs per request (index = 1).
In deployment they would be learned from response-time logs.
"""

import random
import numpy as np

random.seed(42)
np.random.seed(42)

# Pages weighted by access frequency (matches typical web log distributions)
SDSC_PAGES   = ["index","login","search","product","cart","checkout","profile","logout"]
SDSC_WEIGHTS = [0.30,   0.20,  0.15,   0.15,    0.08,  0.05,     0.05,    0.02]

CLARK_PAGES   = ["home","news","sports","tech","login","search","archive","logout"]
CLARK_WEIGHTS = [0.35,  0.20,  0.15,   0.10,  0.08,  0.07,    0.04,    0.01]

SDSC_COST  = {"index": 1.0, "login": 2.0, "search": 3.0, "product": 2.0,
              "cart": 4.0, "checkout": 8.0, "profile": 1.5, "logout": 0.5}
CLARK_COST = {"home": 1.0, "news": 1.5, "sports": 1.5, "tech": 1.5,
              "login": 2.0, "search": 3.0, "archive": 5.0, "logout": 0.5}

ATTACK_TYPES = ["A1", "A2", "A3", "A4", "A5", "A6"]

# Legitimate navigation flow: page -> {next page: probability}
SDSC_FLOW = {
    "index":    {"login": 0.30, "search": 0.35, "product": 0.30, "logout": 0.05},
    "login":    {"index": 0.40, "profile": 0.30, "search": 0.30},
    "search":   {"product": 0.70, "search": 0.15, "index": 0.15},
    "product":  {"cart": 0.35, "search": 0.35, "product": 0.15, "index": 0.15},
    "cart":     {"checkout": 0.60, "product": 0.30, "logout": 0.10},
    "checkout": {"logout": 0.70, "index": 0.30},
    "profile":  {"index": 0.50, "search": 0.30, "logout": 0.20},
    "logout":   {},
}

CLARK_FLOW = {
    "home":    {"news": 0.40, "sports": 0.25, "tech": 0.20, "search": 0.10, "login": 0.05},
    "news":    {"news": 0.30, "home": 0.30, "archive": 0.20, "sports": 0.10, "logout": 0.10},
    "sports":  {"sports": 0.30, "home": 0.40, "news": 0.20, "logout": 0.10},
    "tech":    {"tech": 0.30, "home": 0.40, "archive": 0.20, "logout": 0.10},
    "login":   {"home": 0.80, "archive": 0.20},
    "search":  {"news": 0.40, "tech": 0.30, "archive": 0.30},
    "archive": {"archive": 0.30, "news": 0.30, "home": 0.30, "logout": 0.10},
    "logout":  {},
}


def _think_time():
    """Log-normal think time — matches real web user behaviour (~2s mean)."""
    return round(max(0.1, np.random.lognormal(mean=0.7, sigma=0.8)), 2)


def _power_user_think():
    """Fast but still irregular human — ~1s median."""
    return round(max(0.1, np.random.lognormal(mean=-0.2, sigma=0.6)), 2)


def _fast_think():
    """Attack think time — 0.05 to 0.2 seconds."""
    return round(random.uniform(0.05, 0.20), 2)


def _borderline_think():
    """Slow bot trying to mimic humans — 0.3 to 1.1 seconds."""
    return round(random.uniform(0.30, 1.10), 2)


def _mimic_think():
    """Bot paced like a human (~1.7s) but more regular than real users."""
    return round(max(0.1, np.random.lognormal(mean=0.5, sigma=0.35)), 2)


def _legit_timer():
    return _power_user_think if random.random() < 0.20 else _think_time


def _attack_timer():
    return random.choices([_fast_think, _borderline_think, _mimic_think],
                          weights=[0.40, 0.30, 0.30])[0]


def _walk(flow, start_pages, start_weights, max_len, avoid_logout=False):
    """Follow the navigation flow until logout or max_len pages."""
    pages = [random.choices(start_pages, weights=start_weights)[0]]
    while len(pages) < max_len and flow.get(pages[-1]):
        nxt = dict(flow[pages[-1]])
        if avoid_logout and len(nxt) > 1:
            nxt.pop("logout", None)
        pages.append(random.choices(list(nxt), weights=list(nxt.values()))[0])
    return pages


def _path_bot(flow, start_pages, start_weights):
    """A6: follows real navigation paths (never logging out) with regular,
    machine-like pacing faster than most humans. Bots paced fully like
    humans can't be told apart within one session and don't amplify load;
    they are left to the per-client budget (pta/traffic.py)."""
    lo, hi = random.choice([(0.05, 0.3), (0.3, 0.5), (0.5, 1.0)])
    weights = [0 if p == "logout" else w for p, w in zip(start_pages, start_weights)]
    pages  = _walk(flow, start_pages, weights, random.randint(4, 14),
                   avoid_logout=True)
    return [(p, round(random.uniform(lo, hi), 2)) for p in pages]


def _with_decoy(attack, flow, start_pages, start_weights):
    """30% of attackers open with 1-3 normal-looking requests before the attack,
    so whole-session statistics like page_repetition get diluted."""
    if random.random() >= 0.30:
        return attack
    think = _legit_timer()
    decoy = _walk(flow, start_pages, start_weights, random.randint(1, 3))
    return [(p, think()) for p in decoy] + attack


def generate_sdsc_normal_session():
    pages = _walk(SDSC_FLOW, SDSC_PAGES, SDSC_WEIGHTS, random.randint(3, 8))
    think = _legit_timer()
    return [(p, think()) for p in pages]


def generate_sdsc_attack_session(attack_type="A1"):
    """
    Five attack types from the paper:
    A1 random flood, A2 single-URL flood,
    A3 random asymmetric, A4 single-URL asymmetric, A5 botnet
    plus A6, a bot following real navigation paths (_path_bot).
    A1-A5 pacing is drawn from _attack_timer (flood or human-like),
    and 30% get a decoy prefix of normal browsing (_with_decoy).
    """
    if attack_type == "A6":
        return _path_bot(SDSC_FLOW, SDSC_PAGES, SDSC_WEIGHTS)
    think = _attack_timer()
    if attack_type == "A1":   # random flood
        pages = random.choices(SDSC_PAGES, k=random.randint(5, 10))
    elif attack_type == "A2": # single URL flood
        page  = random.choice(["search", "product", "checkout"])
        pages = [page] * random.randint(5, 10)
    elif attack_type == "A3": # random asymmetric (high workload pages)
        pages = random.choices(["checkout", "cart", "product"], k=random.randint(4, 8))
    elif attack_type == "A4": # single URL asymmetric
        pages = ["checkout"] * random.randint(4, 8)
    else:                     # A5 botnet — scripted sequence
        script = random.choices(SDSC_PAGES, k=4)
        pages  = script * random.randint(2, 4)
    return _with_decoy([(p, think()) for p in pages],
                       SDSC_FLOW, SDSC_PAGES, SDSC_WEIGHTS)


def generate_clark_normal_session():
    pages = _walk(CLARK_FLOW, CLARK_PAGES, CLARK_WEIGHTS, random.randint(2, 6))
    think = _legit_timer()
    return [(p, think()) for p in pages]


def generate_clark_attack_session(attack_type=None):
    attack_type = attack_type or random.choice(ATTACK_TYPES)
    if attack_type == "A6":
        return _path_bot(CLARK_FLOW, CLARK_PAGES, CLARK_WEIGHTS)
    pages_pool  = CLARK_PAGES
    think       = _attack_timer()
    if attack_type in ("A2","A4"):
        page  = random.choice(["news","sports","archive"])
        pages = [page] * random.randint(5, 10)
    elif attack_type == "A5":
        pages = random.choices(pages_pool, k=3) * 3
    else:
        pages = random.choices(pages_pool, k=random.randint(4, 9))
    return _with_decoy([(p, think()) for p in pages],
                       CLARK_FLOW, CLARK_PAGES, CLARK_WEIGHTS)


def _build(n_sessions, seed, legit_gen, attack_gen, return_types):
    random.seed(seed); np.random.seed(seed)
    n_legit = int(n_sessions * 0.80)
    rows = [(legit_gen(), 0, None) for _ in range(n_legit)]
    for i in range(n_sessions - n_legit):
        kind = ATTACK_TYPES[i % len(ATTACK_TYPES)]
        rows.append((attack_gen(kind), 1, kind))
    random.shuffle(rows)
    sessions, labels, types = (list(c) for c in zip(*rows))
    return (sessions, labels, types) if return_types else (sessions, labels)


def build_sdsc_dataset(n_sessions=500, seed=42, return_types=False):
    """
    Returns sessions, labels matching SDSC-HTTP log style.
    80% legitimate, 20% attack (paper methodology), attack types A1-A6 in
    equal shares. Seeded so every script that builds it gets the same
    sessions. With return_types, also returns each session's attack type
    (None for legitimate sessions).
    """
    return _build(n_sessions, seed, generate_sdsc_normal_session,
                  generate_sdsc_attack_session, return_types)


def build_clarknet_dataset(n_sessions=500, seed=42, return_types=False):
    return _build(n_sessions, seed, generate_clark_normal_session,
                  generate_clark_attack_session, return_types)
