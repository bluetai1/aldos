"""
traffic.py
==========
Turning a raw request stream into sessions, and watching site-wide load.

An attacker can't be allowed to choose where one session ends and the next
begins, or it can split an attack into many tiny sessions that are each too
short to judge. So sessions are formed server-side, per client, and a
site-wide meter catches attacks spread across many clients.
"""

from collections import defaultdict, deque


def sessionize(requests, timeout=300.0, end_pages=("logout",)):
    """
    Group requests into sessions per client. A session ends after `timeout`
    seconds of inactivity or after a request to one of `end_pages`.

    requests: iterable of (client_id, timestamp, page), any order.
    Returns a list of (client_id, start_time, session), where session is
    [(page, think_time), ...] and think_time is the gap since that client's
    previous request (capped at `timeout`; 0 for a client's first request).
    """
    by_client = defaultdict(list)
    for client, t, page in requests:
        by_client[client].append((t, page))

    out = []
    for client, reqs in by_client.items():
        reqs.sort()
        current, start, prev_t = [], None, None
        for t, page in reqs:
            gap = 0.0 if prev_t is None else t - prev_t
            if current and (gap > timeout or current[-1][0] in end_pages):
                out.append((client, start, current))
                current = []
            if not current:
                start = t
            current.append((page, round(min(gap, timeout), 3)))
            prev_t = t
        if current:
            out.append((client, start, current))
    return out


class ClientBudget:
    """
    Per-client server cost over a sliding window, across sessions. Catches
    bots that look human request by request but keep going far longer than
    any real visitor, which is the only way a human-paced bot adds load.
    """

    def __init__(self, page_cost, limit, window=600.0):
        self.page_cost = page_cost
        self.limit     = limit
        self.window    = window
        self._events   = defaultdict(deque)   # client -> (timestamp, cost)
        self._totals   = defaultdict(float)

    @classmethod
    def calibrate(cls, normal_sessions, page_cost, window=600.0, factor=2.0):
        """Limit = `factor` × the costliest legitimate session (a visitor's
        whole session fits in one window)."""
        peak = max(sum(page_cost.get(p, 1.0) for p, _ in s) for s in normal_sessions)
        return cls(page_cost, factor * peak, window)

    def record(self, client, t, page):
        ev = self._events[client]
        ev.append((t, self.page_cost.get(page, 1.0)))
        self._totals[client] += ev[-1][1]
        while ev and ev[0][0] < t - self.window:
            self._totals[client] -= ev.popleft()[1]

    def over_budget(self, client):
        return self._totals[client] > self.limit


class LoadGuard:
    """
    Site-wide server cost per second over a sliding window. Sessions too
    short to judge one by one (e.g. a botnet sending one request per IP) are
    challenged while the cost rate is above `limit`.
    """

    def __init__(self, page_cost, limit, window=10.0):
        self.page_cost = page_cost
        self.limit     = limit
        self.window    = window
        self._events   = deque()          # (timestamp, cost)
        self._total    = 0.0

    @classmethod
    def calibrate(cls, normal_requests, page_cost, window=10.0, factor=2.0):
        """Set the limit to `factor` × the busiest window seen in normal traffic."""
        guard = cls(page_cost, limit=float("inf"), window=window)
        peak  = 0.0
        for _, t, page in sorted(normal_requests, key=lambda r: r[1]):
            guard.record(t, page)
            peak = max(peak, guard.cost_rate())
        guard.limit = factor * peak
        guard._events.clear(); guard._total = 0.0
        return guard

    def record(self, t, page):
        cost = self.page_cost.get(page, 1.0)
        self._events.append((t, cost))
        self._total += cost
        while self._events and self._events[0][0] < t - self.window:
            self._total -= self._events.popleft()[1]

    def cost_rate(self):
        return self._total / self.window

    def under_load(self):
        return self.cost_rate() > self.limit
