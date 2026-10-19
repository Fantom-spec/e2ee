"""Registration, login, session validation and logout against a real database."""

import sqlite3

from app import auth_service, repo
from app.auth_service import AuthError
from app.security import PasswordHasher, token_digest
from app.validation import ValidationError
from helpers import NOW, PASSWORD, SECRET, DbTestCase, fast_hasher


class CountingHasher(PasswordHasher):
    def __init__(self) -> None:
        super().__init__(log_n=10)
        self.verify_calls = 0

    def verify(self, stored: str, password: str) -> bool:
        self.verify_calls += 1
        return super().verify(stored, password)


class RegistrationTests(DbTestCase):
    def test_register_and_duplicate_username(self) -> None:
        self.make_user("alice")
        with self.assertRaises(repo.UsernameTaken):
            self.make_user("ALICE")

    def test_invalid_inputs_rejected_before_any_write(self) -> None:
        c = self.conn()
        for args in (("a!", "A", PASSWORD), ("alice", "", PASSWORD), ("alice", "A", "short")):
            with self.subTest(args=args), self.assertRaises(ValidationError):
                auth_service.register(c, self.hasher, *args, NOW)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)

    def test_password_is_not_stored_in_plaintext_anywhere(self) -> None:
        self.make_user("alice", "unique-marker-password-9")
        c = self.conn()
        stored = c.execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertTrue(stored.startswith("scrypt$"))
        c.close()
        self.assertNotIn(b"unique-marker-password-9", self.db_bytes())

    def test_sql_injection_in_username_is_just_invalid(self) -> None:
        with self.assertRaises(ValidationError):
            self.make_user("x'); DROP TABLE users;--")
        self.assertEqual(self.conn().execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)


class LoginTests(DbTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.uid = self.make_user("alice")

    def test_login_and_authenticate(self) -> None:
        result = self.login("Alice")  # case-insensitive username
        self.assertEqual(result.context.user_id, self.uid)
        ctx = auth_service.authenticate(self.conn(), SECRET, result.token, NOW + 5)
        self.assertEqual(ctx, result.context)
        self.assertEqual(result.expires_at, NOW + 86_400)

    def test_raw_token_never_stored_only_its_digest(self) -> None:
        result = self.login("alice")
        self.assertNotIn(result.token.encode(), self.db_bytes())
        self.assertIn(token_digest(result.token, SECRET).encode(), self.db_bytes())

    def test_wrong_password_and_unknown_user_are_indistinguishable(self) -> None:
        c = self.conn()
        for user, pw in (("alice", "wrong-password-123"), ("nobody", PASSWORD), ("!!", PASSWORD)):
            with self.subTest(user=user), self.assertRaises(AuthError) as cm:
                auth_service.login(c, self.hasher, SECRET, user, pw, NOW, 100)
            self.assertEqual(str(cm.exception), "")

    def test_unknown_user_still_costs_one_verification(self) -> None:
        hasher = CountingHasher()
        hasher.dummy_hash  # precompute so only login's own verify is counted
        hasher.verify_calls = 0
        with self.assertRaises(AuthError):
            auth_service.login(self.conn(), hasher, SECRET, "nobody", PASSWORD, NOW, 100)
        self.assertEqual(hasher.verify_calls, 1)

    def test_disabled_user_cannot_log_in_or_use_existing_session(self) -> None:
        result = self.login("alice")
        c = self.conn()
        c.execute("UPDATE users SET disabled = 1 WHERE id = ?", (self.uid,))
        c.commit()
        with self.assertRaises(AuthError):
            auth_service.login(c, self.hasher, SECRET, "alice", PASSWORD, NOW, 100)
        self.assertIsNone(auth_service.authenticate(c, SECRET, result.token, NOW + 1))

    def test_session_expires(self) -> None:
        result = self.login("alice", ttl=60)
        c = self.conn()
        self.assertIsNotNone(auth_service.authenticate(c, SECRET, result.token, NOW + 59))
        self.assertIsNone(auth_service.authenticate(c, SECRET, result.token, NOW + 60))

    def test_logout_revokes_session(self) -> None:
        result = self.login("alice")
        c = self.conn()
        auth_service.logout(c, result.context.session_id, NOW + 1)
        c.commit()
        self.assertIsNone(auth_service.authenticate(c, SECRET, result.token, NOW + 2))
        self.assertFalse(repo.session_is_active(c, result.context.session_id, NOW + 2))

    def test_garbage_and_foreign_tokens_rejected(self) -> None:
        result = self.login("alice")
        c = self.conn()
        for bad in ("", "x", "a" * 300, result.token[:-1] + ("A" if result.token[-1] != "A" else "B")):
            self.assertIsNone(auth_service.authenticate(c, SECRET, bad, NOW))
        # Same token checked under a different server secret must fail.
        self.assertIsNone(auth_service.authenticate(c, "other-secret-" + "x" * 30, result.token, NOW))

    def test_each_login_creates_an_independent_session(self) -> None:
        a, b = self.login("alice"), self.login("alice")
        self.assertNotEqual(a.token, b.token)
        c = self.conn()
        auth_service.logout(c, a.context.session_id, NOW + 1)
        c.commit()
        self.assertIsNone(auth_service.authenticate(c, SECRET, a.token, NOW + 2))
        self.assertIsNotNone(auth_service.authenticate(c, SECRET, b.token, NOW + 2))


class SearchTests(DbTestCase):
    def test_prefix_search_excludes_self_disabled_and_escapes_wildcards(self) -> None:
        me = self.make_user("alice")
        self.make_user("alina")
        self.make_user("bob_x")
        gone = self.make_user("alone")
        c = self.conn()
        c.execute("UPDATE users SET disabled = 1 WHERE id = ?", (gone,))
        c.commit()
        names = [r["username"] for r in repo.search_users(c, "al", me)]
        self.assertEqual(names, ["alina"])
        self.assertEqual(repo.search_users(c, "%", me), [])
        # "_" and "%" are literals, not SQL wildcards: "b_" must not match "bob_x".
        self.assertEqual(repo.search_users(c, "b_", me), [])
        self.assertEqual(repo.search_users(c, "_o", me), [])
        self.assertEqual(repo.search_users(c, "bob_", me)[0]["username"], "bob_x")
        for row in repo.search_users(c, "bo", me):
            self.assertEqual(set(row.keys()), {"id", "username", "display_name"})  # no hashes leak


if __name__ == "__main__":
    import unittest
    unittest.main()
