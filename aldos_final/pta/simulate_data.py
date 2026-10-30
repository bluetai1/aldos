import random
import numpy as np

def generate_normal_session():
    return [
        ("login",     round(random.uniform(1.5, 3.5), 2)),
        ("dashboard", round(random.uniform(2.0, 5.0), 2)),
        ("profile",   round(random.uniform(2.0, 5.0), 2)),
        ("logout",    round(random.uniform(1.0, 3.0), 2)),
    ]

def generate_attack_session():
    pages = ["login", "login", "login", "dashboard", "search"]
    return [(page, round(random.uniform(0.05, 0.15), 2)) for page in pages]

def generate_single_url_flood_session():
    """One page hammered repeatedly — the paper's A2/A4 attack."""
    page = random.choice(["search", "dashboard", "login", "profile"])
    return [(page, round(random.uniform(0.05, 0.3), 2))
            for _ in range(random.randint(4, 8))]

def generate_borderline_session():
    """Slow bot — mimics human timing but repeats pages."""
    return [
        ("login",     round(random.uniform(0.8, 1.5), 2)),
        ("dashboard", round(random.uniform(0.2, 0.5), 2)),
        ("search",    round(random.uniform(0.1, 0.4), 2)),
        ("search",    round(random.uniform(0.1, 0.4), 2)),
        ("logout",    round(random.uniform(0.5, 1.2), 2)),
    ]

def generate_noisy_normal_session():
    """Fast legitimate user — overlaps with bot range."""
    pages = random.choice([
        ["login", "dashboard", "logout"],
        ["login", "search", "search", "dashboard", "logout"],
        ["login", "dashboard", "profile", "dashboard", "logout"],
    ])
    return [(p, round(random.uniform(0.4, 1.4), 2)) for p in pages]

def generate_noisy_attack_session():
    """Bot with artificial delays — overlaps with human range."""
    pages = random.choice([
        ["login", "search", "login", "search", "login"],
        ["dashboard", "search", "search", "dashboard", "search"],
        ["login", "login", "dashboard", "search", "search", "logout"],
    ])
    return [(p, round(random.uniform(0.3, 1.1), 2)) for p in pages]

def generate_grey_area_session(label):
    """
    Sessions that sit in the genuine grey zone — the training data
    the Decision Tree needs to produce 35–70% probabilities.
    label=0 → ambiguous legitimate, label=1 → ambiguous attack.
    """
    if label == 0:
        # Power user or mobile user with fast but varied browsing
        n = random.randint(3, 5)
        page_pool = ["login","dashboard","search","profile","logout"]
        pages = [random.choice(page_pool) for _ in range(n)]
        times = [round(random.uniform(0.35, 0.85), 2) for _ in pages]
        return list(zip(pages, times))
    else:
        # Careful bot that spaces requests but still repeats
        page_pool = ["search","dashboard","login","search","dashboard"]
        n = random.randint(4, 6)
        pages = [page_pool[i % len(page_pool)] for i in range(n)]
        times = [round(random.uniform(0.4, 1.3), 2) for _ in pages]
        return list(zip(pages, times))

def create_dataset(n=100):
    sessions, labels = [], []

    # Clean legitimate
    for _ in range(n // 3):
        sessions.append(generate_normal_session()); labels.append(0)

    # Noisy legitimate
    for _ in range(n // 4):
        sessions.append(generate_noisy_normal_session()); labels.append(0)

    # Grey-area legitimate (the 35-70% zone)
    for _ in range(n // 4):
        sessions.append(generate_grey_area_session(0)); labels.append(0)

    # Clear attacks
    for _ in range(n // 3):
        sessions.append(generate_attack_session()); labels.append(1)

    # Single-URL floods
    for _ in range(n // 4):
        sessions.append(generate_single_url_flood_session()); labels.append(1)

    # Borderline bots
    for _ in range(n // 4):
        sessions.append(generate_borderline_session()); labels.append(1)

    # Noisy attacks
    for _ in range(n // 4):
        sessions.append(generate_noisy_attack_session()); labels.append(1)

    # Grey-area attacks (the 35-70% zone)
    for _ in range(n // 4):
        sessions.append(generate_grey_area_session(1)); labels.append(1)

    return sessions, labels
