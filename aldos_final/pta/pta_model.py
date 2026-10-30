import networkx as nx
import numpy as np
from collections import defaultdict

class PTAModel:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.known_pages   = None   # None = hand-built graph, every page "known"
        self.page_workload = {}

    def learn(self, sessions, labels, page_cost=None):
        """Build transitions from the legitimate (label 0) sessions:
        prob = share of exits from src, think-time mean/std per edge.
        With page_cost, workload W = cost of the destination page relative
        to the average legitimate request (so W averages 1)."""
        times = defaultdict(lambda: defaultdict(list))
        self.known_pages = set()
        for session, label in zip(sessions, labels):
            if label != 0:
                continue
            self.known_pages.update(p for p, _ in session)
            for i in range(len(session) - 1):
                src, _       = session[i]
                dst, think_t = session[i + 1]
                times[src][dst].append(think_t)
        avg_cost = 1.0
        if page_cost:
            dst_costs = [page_cost.get(dst, 1.0) * len(ts)
                         for dsts in times.values() for dst, ts in dsts.items()]
            n_trans   = sum(len(ts) for dsts in times.values() for ts in dsts.values())
            avg_cost  = sum(dst_costs) / n_trans
        self.page_workload = {p: (page_cost.get(p, 1.0) / avg_cost if page_cost else 1.0)
                              for p in self.known_pages}
        self.graph.clear()
        for src, dsts in times.items():
            total = sum(len(ts) for ts in dsts.values())
            for dst, ts in dsts.items():
                self.add_transition(src, dst, len(ts) / total,
                                    float(np.mean(ts)), float(np.std(ts)),
                                    self.page_workload[dst])

    def knows(self, page):
        return self.known_pages is None or page in self.known_pages

    def unknown_page_share(self, sessions):
        """Drift monitor: share of requests to pages absent from training.
        A jump means the site changed and the PTA should be relearned."""
        pages = [p for s in sessions for p, _ in s]
        return sum(not self.knows(p) for p in pages) / max(len(pages), 1)

    def add_transition(self, src, dst, prob, mean_time, std_time, workload=1.0):
        self.graph.add_edge(src, dst, prob=prob, mean_time=mean_time,
                            std_time=std_time, workload=workload)

    def get_transition(self, src, dst):
        return self.graph.get_edge_data(src, dst, default=None)

    def get_all_states(self):
        return list(self.graph.nodes)
