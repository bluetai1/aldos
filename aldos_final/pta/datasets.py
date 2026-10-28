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


def _walk(flow, start_pages, start_weights, max_len):
    """Follow the navigation flow until logout or max_len pages."""
    pages = [random.choices(start_pages, weights=start_weights)[0]]
    while len(pages) < max_len and flow.get(pages[-1]):
        nxt = flow[pages[-1]]
        pages.append(random.choices(list(nxt), weights=list(nxt.values()))[0])
    return pages


def generate_sdsc_normal_session():
    pages = _walk(SDSC_FLOW, SDSC_PAGES, SDSC_WEIGHTS, random.randint(3, 8))
    think = _legit_timer()
    return [(p, think()) for p in pages]


def generate_sdsc_attack_session(attack_type="flood"):
    """
    Five attack types from the paper:
    A1 random flood, A2 single-URL flood,
    A3 random asymmetric, A4 single-URL asymmetric, A5 botnet
    Each session's pacing is drawn from _attack_timer (flood or human-like).
    """
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
    return [(p, think()) for p in pages]


def generate_clark_normal_session():
    pages = _walk(CLARK_FLOW, CLARK_PAGES, CLARK_WEIGHTS, random.randint(2, 6))
    think = _legit_timer()
    return [(p, think()) for p in pages]


def generate_clark_attack_session():
    attack_type = random.choice(["A1","A2","A3","A4","A5"])
    pages_pool  = CLARK_PAGES
    think       = _attack_timer()
    if attack_type in ("A2","A4"):
        page  = random.choice(["news","sports","archive"])
        pages = [page] * random.randint(5, 10)
    elif attack_type == "A5":
        pages = random.choices(pages_pool, k=3) * 3
    else:
        pages = random.choices(pages_pool, k=random.randint(4, 9))
    return [(p, think()) for p in pages]


def build_sdsc_dataset(n_sessions=500, seed=42):
    """
    Returns sessions, labels matching SDSC-HTTP log style.
    80% legitimate, 20% attack (paper methodology).
    Seeded so every script that builds it gets the same sessions.
    """
    random.seed(seed); np.random.seed(seed)
    sessions, labels = [], []
    n_legit  = int(n_sessions * 0.80)
    n_attack = n_sessions - n_legit
    for _ in range(n_legit):
        sessions.append(generate_sdsc_normal_session()); labels.append(0)
    attack_types = ["A1","A2","A3","A4","A5"]
    for i in range(n_attack):
        sessions.append(generate_sdsc_attack_session(attack_types[i % 5]))
        labels.append(1)
    combined = list(zip(sessions, labels))
    random.shuffle(combined)
    sessions, labels = zip(*combined)
    return list(sessions), list(labels)


def build_clarknet_dataset(n_sessions=500, seed=42):
    random.seed(seed); np.random.seed(seed)
    sessions, labels = [], []
    n_legit  = int(n_sessions * 0.80)
    n_attack = n_sessions - n_legit
    for _ in range(n_legit):
        sessions.append(generate_clark_normal_session()); labels.append(0)
    for _ in range(n_attack):
        sessions.append(generate_clark_attack_session()); labels.append(1)
    combined = list(zip(sessions, labels))
    random.shuffle(combined)
    sessions, labels = zip(*combined)
    return list(sessions), list(labels)
