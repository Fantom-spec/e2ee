import unittest

from app.ratelimit import RateLimiter
from app.tickets import TicketStore


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class RateLimiterTests(unittest.TestCase):
    def test_blocks_after_limit_and_recovers(self) -> None:
        clock = Clock()
        rl = RateLimiter(3, 10, clock)
        self.assertTrue(all(rl.allow("k") for _ in range(3)))
        self.assertFalse(rl.allow("k"))
        self.assertGreaterEqual(rl.retry_after("k"), 1)
        clock.t += 10.01
        self.assertTrue(rl.allow("k"))

    def test_keys_are_independent(self) -> None:
        rl = RateLimiter(1, 10, Clock())
        self.assertTrue(rl.allow("a"))
        self.assertFalse(rl.allow("a"))
        self.assertTrue(rl.allow("b"))

    def test_denied_attempts_do_not_extend_the_block(self) -> None:
        clock = Clock()
        rl = RateLimiter(1, 10, clock)
        rl.allow("k")
        for _ in range(50):
            clock.t += 0.1
            self.assertFalse(rl.allow("k"))
        clock.t += 6.0  # 11 s after the only recorded event
        self.assertTrue(rl.allow("k"))

    def test_reset(self) -> None:
        rl = RateLimiter(1, 10, Clock())
        rl.allow("k")
        rl.reset("k")
        self.assertTrue(rl.allow("k"))

    def test_expired_keys_are_collected(self) -> None:
        clock = Clock()
        rl = RateLimiter(1, 1, clock)
        for i in range(500):
            rl.allow(f"k{i}")
        clock.t += 5
        for i in range(500):  # drives the periodic collection
            rl.allow("same")
        self.assertLess(len(rl._events), 10)

    def test_invalid_configuration(self) -> None:
        with self.assertRaises(ValueError):
            RateLimiter(0, 10)


class TicketTests(unittest.TestCase):
    def test_single_use(self) -> None:
        ts = TicketStore(clock=Clock())
        t = ts.issue("u1", "s1")
        self.assertEqual(ts.consume(t), ("u1", "s1"))
        self.assertIsNone(ts.consume(t))

    def test_expiry(self) -> None:
        clock = Clock()
        ts = TicketStore(ttl=30, clock=clock)
        t = ts.issue("u1", "s1")
        clock.t += 31
        self.assertIsNone(ts.consume(t))

    def test_unknown_and_malformed(self) -> None:
        ts = TicketStore(clock=Clock())
        ts.issue("u1", "s1")
        for bad in ("", "nope", "x" * 500):
            self.assertIsNone(ts.consume(bad))

    def test_tickets_are_unique(self) -> None:
        ts = TicketStore(clock=Clock())
        self.assertEqual(len({ts.issue("u", "s") for _ in range(100)}), 100)


if __name__ == "__main__":
    unittest.main()
