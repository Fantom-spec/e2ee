"""Request-model tests (need pydantic only; skipped visibly if it is missing)."""

import unittest

try:
    from pydantic import ValidationError as PydanticError

    from app.schemas import KeyUploadRequest, LoginRequest, RegisterRequest

    HAVE_PYDANTIC = True
except ImportError:  # pragma: no cover
    HAVE_PYDANTIC = False


@unittest.skipUnless(HAVE_PYDANTIC, "pydantic not installed in this environment")
class SchemaTests(unittest.TestCase):
    def test_register_normalises_fields(self) -> None:
        r = RegisterRequest(username=" Alice ", display_name="  Alice B ", password="long-enough-pw")
        self.assertEqual((r.username, r.display_name), ("alice", "Alice B"))

    def test_register_rejects_bad_values(self) -> None:
        for kwargs in (
            dict(username="a", display_name="A", password="long-enough-pw"),
            dict(username="alice", display_name="", password="long-enough-pw"),
            dict(username="alice", display_name="A", password="short"),
            dict(username="alice", display_name="A", password="x" * 257),
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(PydanticError):
                RegisterRequest(**kwargs)

    def test_unknown_fields_are_forbidden(self) -> None:
        with self.assertRaises(PydanticError):
            RegisterRequest(username="alice", display_name="A", password="long-enough-pw", is_admin=True)
        with self.assertRaises(PydanticError):
            LoginRequest(username="alice", password="x", role="admin")

    def test_error_details_can_be_stripped_of_input(self) -> None:
        """Mirrors the app's 422 handler: loc + msg only, never the submitted value."""
        with self.assertRaises(PydanticError) as cm:
            RegisterRequest(username="alice", display_name="A", password="Zq9-short")
        safe = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in cm.exception.errors()]
        self.assertNotIn("Zq9-short", repr(safe))

    def test_key_upload_validation(self) -> None:
        import base64

        key = base64.b64encode(bytes([7]) * 33).decode()
        sig = base64.b64encode(bytes([8]) * 64).decode()
        good = dict(registration_id=5, identity_public=key,
                    signed_prekey=dict(id=1, public=key, signature=sig),
                    one_time_prekeys=[dict(id=1, public=key)])
        self.assertEqual(KeyUploadRequest(**good).registration_id, 5)
        for bad in (
            {**good, "identity_public": "not base64!"},
            {**good, "signed_prekey": dict(id=1, public=key, signature=key)},   # signature too short
            {**good, "registration_id": -1},
            {**good, "one_time_prekeys": [dict(id=1, public=key)] * 101},
            {**good, "extra": 1},
            {**good, "signed_prekey": dict(id=1, public=key, signature=sig, private="x")},
        ):
            with self.subTest(bad=list(bad)), self.assertRaises(PydanticError):
                KeyUploadRequest(**bad)

    def test_login_accepts_any_password_shape(self) -> None:
        self.assertEqual(LoginRequest(username="x", password="p").password, "p")


if __name__ == "__main__":
    unittest.main()
