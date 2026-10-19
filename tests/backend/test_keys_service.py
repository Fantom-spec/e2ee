"""Key directory against a real SQLite database (no web framework needed)."""

import base64
import sqlite3
import unittest

from app import keys_service, repo
from app.keys_service import KeyConflict, parse_upload, publish_keys
from app.validation import ValidationError
from helpers import NOW, DbTestCase


def b64(n: int, fill: int = 1, length: int = 33) -> str:
    return base64.b64encode(bytes([(fill + n) % 256]) * length).decode()


def upload(identity: int = 1, otps: tuple[int, ...] = (1, 2, 3), spk_id: int = 7, reg: int = 1234) -> dict:
    return {
        "registration_id": reg,
        "identity_public": b64(identity, fill=10),
        "signed_prekey": {"id": spk_id, "public": b64(spk_id, fill=50),
                          "signature": base64.b64encode(bytes([9]) * 64).decode()},
        "one_time_prekeys": [{"id": i, "public": b64(i, fill=100)} for i in otps],
    }


class ParseTests(unittest.TestCase):
    def test_valid_upload_parses(self) -> None:
        u = parse_upload(upload())
        self.assertEqual(len(u.one_time_prekeys), 3)
        self.assertEqual(u.signed_prekey.key_id, 7)

    def test_invalid_uploads_rejected(self) -> None:
        good = upload()
        bad_variants = {
            "missing signed prekey": {k: v for k, v in good.items() if k != "signed_prekey"},
            "bad registration id": {**good, "registration_id": -1},
            "bool registration id": {**good, "registration_id": True},
            "identity not base64": {**good, "identity_public": "***"},
            "identity too short": {**good, "identity_public": base64.b64encode(b"x" * 8).decode()},
            "identity too long": {**good, "identity_public": base64.b64encode(b"x" * 80).decode()},
            "non-canonical base64": {**good, "identity_public":
                                     base64.b64encode(bytes([5]) * 32).decode().rstrip("=")},
            "short signature": {**good, "signed_prekey": {**good["signed_prekey"],
                                "signature": base64.b64encode(b"x" * 10).decode()}},
            "too many one-time prekeys": {**good, "one_time_prekeys": [
                {"id": i, "public": b64(i)} for i in range(101)]},
            "duplicate ids": {**good, "one_time_prekeys": [{"id": 1, "public": b64(1)}, {"id": 1, "public": b64(2)}]},
            "negative key id": {**good, "one_time_prekeys": [{"id": -3, "public": b64(1)}]},
            "otp not an object": {**good, "one_time_prekeys": ["x"]},
        }
        for name, raw in bad_variants.items():
            with self.subTest(name), self.assertRaises(ValidationError):
                parse_upload(raw)


class PublishFetchTests(DbTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.alice = self.make_user("alice")
        self.bobby = self.make_user("bobby")

    def publish(self, user_id: str, **kwargs):
        c = self.conn()
        result = publish_keys(c, user_id, parse_upload(upload(**kwargs)), NOW)
        c.commit()
        return result

    def test_first_upload_binds_identity(self) -> None:
        r = self.publish(self.alice)
        self.assertEqual((r.identity_changed, r.key_version, r.one_time_prekeys_remaining), (False, 1, 3))
        self.assertEqual(keys_service.key_status(self.conn(), self.alice),
                         {"has_keys": True, "key_version": 1, "one_time_prekeys_remaining": 3})
        self.assertEqual(keys_service.key_status(self.conn(), self.bobby)["has_keys"], False)

    def test_bundle_has_public_material_only_and_consumes_one_time_prekeys_once(self) -> None:
        self.publish(self.alice, otps=(1, 2))
        seen = []
        for _ in range(3):
            c = self.conn()
            bundle = keys_service.fetch_bundle(c, self.alice)
            c.commit()
            seen.append(bundle["one_time_prekey"])
        self.assertEqual([s["id"] for s in seen[:2]], [1, 2])   # each handed out once
        self.assertIsNone(seen[2])                              # exhausted: signed prekey only
        self.assertEqual(set(bundle), {"user_id", "registration_id", "identity_public", "key_version",
                                       "signed_prekey", "one_time_prekey"})
        self.assertEqual(keys_service.key_status(self.conn(), self.alice)["one_time_prekeys_remaining"], 0)

    def test_fetch_without_keys_or_for_unknown_or_disabled_user(self) -> None:
        c = self.conn()
        self.assertIsNone(keys_service.fetch_bundle(c, self.bobby))                       # no keys yet
        self.assertIsNone(keys_service.fetch_bundle(c, "00000000-0000-0000-0000-000000000000"))
        self.publish(self.alice)
        c.execute("UPDATE users SET disabled = 1 WHERE id = ?", (self.alice,))
        c.commit()
        self.assertIsNone(keys_service.fetch_bundle(c, self.alice))
        self.assertIsNone(keys_service.get_identity(c, self.alice))

    def test_same_identity_refresh_keeps_version_and_adds_prekeys(self) -> None:
        self.publish(self.alice, otps=(1, 2))
        r = self.publish(self.alice, otps=(2, 3, 4), spk_id=8)   # id 2 re-sent identically
        self.assertEqual((r.identity_changed, r.key_version, r.one_time_prekeys_remaining), (False, 1, 4))
        ident = keys_service.get_identity(self.conn(), self.alice)
        self.assertEqual(ident["key_version"], 1)
        self.assertEqual(self.conn().execute("SELECT signed_prekey_id FROM identity_keys").fetchone()[0], 8)

    def test_identity_change_bumps_version_records_history_and_drops_old_prekeys(self) -> None:
        self.publish(self.alice, identity=1, otps=(1, 2, 3))
        old = keys_service.get_identity(self.conn(), self.alice)["identity_public"]
        r = self.publish(self.alice, identity=2, otps=(10,))
        self.assertTrue(r.identity_changed)
        self.assertEqual((r.key_version, r.one_time_prekeys_remaining), (2, 1))
        new = keys_service.get_identity(self.conn(), self.alice)
        self.assertNotEqual(new["identity_public"], old)
        self.assertEqual(new["key_version"], 2)
        self.assertEqual(list(keys_service.history_versions(self.conn(), self.alice)), [1, 2])
        # Old one-time prekeys belonged to the old identity and must not be served.
        bundle = keys_service.fetch_bundle(self.conn(), self.alice)
        self.assertEqual(bundle["one_time_prekey"]["id"], 10)

    def test_conflicting_one_time_prekey_id_is_rejected_and_rolled_back(self) -> None:
        self.publish(self.alice, otps=(1,))
        c = self.conn()
        evil = upload(otps=(1,))
        evil["one_time_prekeys"][0]["public"] = b64(99, fill=200)
        with self.assertRaises(KeyConflict):
            publish_keys(c, self.alice, parse_upload(evil), NOW)
        c.rollback()
        row = repo.get_one_time_prekey(self.conn(), self.alice, 1)
        self.assertEqual(row["public_key"], b64(1, fill=100))

    def test_stored_prekey_cap(self) -> None:
        self.publish(self.alice, otps=tuple(range(100)))
        c = self.conn()
        with self.assertRaises(ValidationError):
            publish_keys(c, self.alice, parse_upload(upload(otps=(500,))), NOW)
        c.rollback()
        self.assertEqual(keys_service.key_status(self.conn(), self.alice)["one_time_prekeys_remaining"], 100)

    def test_keys_are_per_user(self) -> None:
        self.publish(self.alice, identity=1)
        self.publish(self.bobby, identity=2)
        a = keys_service.get_identity(self.conn(), self.alice)["identity_public"]
        b = keys_service.get_identity(self.conn(), self.bobby)["identity_public"]
        self.assertNotEqual(a, b)

    def test_concurrent_fetches_never_hand_out_the_same_prekey(self) -> None:
        """Two connections race for the last one-time prekey; exactly one gets it."""
        self.publish(self.alice, otps=(1,))
        c1, c2 = self.conn(), self.conn()
        first = keys_service.fetch_bundle(c1, self.alice)   # holds the write lock
        c2.execute("PRAGMA busy_timeout = 0")
        with self.assertRaises(sqlite3.OperationalError):    # second cannot start until first commits
            keys_service.fetch_bundle(c2, self.alice)
        c1.commit()
        second = keys_service.fetch_bundle(c2, self.alice)
        c2.commit()
        self.assertIsNotNone(first["one_time_prekey"])
        self.assertIsNone(second["one_time_prekey"])

    def test_no_private_key_columns_exist_for_key_tables(self) -> None:
        c = self.conn()
        for table in ("identity_keys", "identity_key_history", "one_time_prekeys"):
            for col in c.execute(f"PRAGMA table_info({table})"):
                self.assertNotIn("private", col["name"])


if __name__ == "__main__":
    unittest.main()
