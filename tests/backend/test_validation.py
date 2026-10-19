import base64
import unittest

from app.validation import (
    ValidationError,
    normalize_username,
    validate_display_name,
    validate_envelope,
    validate_password,
    validate_search_query,
    validate_uuid,
)

UUID = "123e4567-e89b-12d3-a456-426614174000"


class ValidationTests(unittest.TestCase):
    def test_username_is_normalised(self) -> None:
        self.assertEqual(normalize_username("  Alice_01 "), "alice_01")

    def test_bad_usernames_rejected(self) -> None:
        for bad in ("ab", "a" * 33, "has space", "dash-ed", "émile", "a;drop", "", None, 5):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                normalize_username(bad)

    def test_display_name_rules(self) -> None:
        self.assertEqual(validate_display_name("  Alice B. "), "Alice B.")
        for bad in ("", "   ", "x" * 65, "evil‮name", "tab\there", "nul\x00", 7):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                validate_display_name(bad)

    def test_password_rules(self) -> None:
        validate_password("a" * 10)
        for bad in ("short", "a" * 129, " " * 12, "has\x00nul12345", None):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                validate_password(bad)

    def test_uuid(self) -> None:
        self.assertEqual(validate_uuid(UUID.upper()), UUID)
        for bad in ("", "not-a-uuid", UUID + "0", UUID[:-1], None, 3):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                validate_uuid(bad)

    def test_search_query(self) -> None:
        self.assertEqual(validate_search_query(" Al "), "al")
        for bad in ("a", "x" * 33, "a%", "a_b c", "a'--", None):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                validate_search_query(bad)

    def test_envelope_rules(self) -> None:
        good = base64.b64encode(b"\x00\x01opaque").decode()
        self.assertEqual(validate_envelope(good, 100), good)
        for bad in ("", "not base64!!", "abc", good * 50, None, 5, "AAAA\n"):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                validate_envelope(bad, 100)


if __name__ == "__main__":
    unittest.main()
