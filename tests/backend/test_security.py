import unittest

from app.security import PasswordHasher, new_id, new_token, token_digest


class PasswordHasherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = PasswordHasher(log_n=10)

    def test_round_trip(self) -> None:
        stored = self.h.hash("correct horse battery")
        self.assertTrue(stored.startswith("scrypt$1024$8$1$"))
        self.assertTrue(self.h.verify(stored, "correct horse battery"))
        self.assertFalse(self.h.verify(stored, "correct horse batterY"))

    def test_hash_contains_no_plaintext_and_is_salted(self) -> None:
        a, b = self.h.hash("same-password-1"), self.h.hash("same-password-1")
        self.assertNotEqual(a, b)
        self.assertNotIn("same-password-1", a)

    def test_malformed_stored_values_fail_closed(self) -> None:
        for bad in ("", "plaintext", "scrypt$x$8$1$AA==$AA==", "md5$1024$8$1$AA==$AA==",
                    "scrypt$1024$8$1$!!$AA==", "scrypt$1000$8$1$AA==$AA=="):
            with self.subTest(bad=bad):
                self.assertFalse(self.h.verify(bad, "whatever"))

    def test_absurd_cost_parameters_are_refused(self) -> None:
        stored = self.h.hash("pw-for-cost-check")
        huge = stored.replace("$1024$", f"${2**30}$", 1)
        self.assertFalse(self.h.verify(huge, "pw-for-cost-check"))

    def test_hasher_rejects_weak_configuration(self) -> None:
        with self.assertRaises(ValueError):
            PasswordHasher(log_n=4)

    def test_dummy_hash_is_valid_but_matches_nothing_guessable(self) -> None:
        self.assertTrue(self.h.dummy_hash.startswith("scrypt$"))
        self.assertFalse(self.h.verify(self.h.dummy_hash, "password"))


class TokenTests(unittest.TestCase):
    def test_tokens_are_unique_and_long(self) -> None:
        tokens = {new_token() for _ in range(200)}
        self.assertEqual(len(tokens), 200)
        self.assertTrue(all(len(t) >= 40 for t in tokens))

    def test_digest_is_keyed_and_deterministic(self) -> None:
        t = new_token()
        self.assertEqual(token_digest(t, "k" * 40), token_digest(t, "k" * 40))
        self.assertNotEqual(token_digest(t, "k" * 40), token_digest(t, "j" * 40))
        self.assertNotIn(t, token_digest(t, "k" * 40))

    def test_ids_are_uuids(self) -> None:
        self.assertEqual(len(new_id()), 36)


if __name__ == "__main__":
    unittest.main()
