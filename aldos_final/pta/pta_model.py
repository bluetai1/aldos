import networkx as nx
import numpy as np
from collections import defaultdict

class PTAModel:
    def __init__(self):
        self.graph = nx.DiGraph()

    def learn(self, sessions, labels):
        """Build transitions from the legitimate (label 0) sessions:
        prob = share of exits from src, think-time mean/std per edge."""
        times = defaultdict(lambda: defaultdict(list))
        for session, label in zip(sessions, labels):
            if label != 0:
                continue
            for i in range(len(session) - 1):
                src, _       = session[i]
                dst, think_t = session[i + 1]
                times[src][dst].append(think_t)
        self.graph.clear()
        for src, dsts in times.items():
            total = sum(len(ts) for ts in dsts.values())
            for dst, ts in dsts.items():
                self.add_transition(src, dst, len(ts) / total,
                                    float(np.mean(ts)), float(np.std(ts)))

    def add_transition(self, src, dst, prob, mean_time, std_time, workload=1.0):
        self.graph.add_edge(src, dst, prob=prob, mean_time=mean_time,
                            std_time=std_time, workload=workload)

    def get_transition(self, src, dst):
        return self.graph.get_edge_data(src, dst, default=None)

    def get_all_states(self):
        return list(self.graph.nodes)
