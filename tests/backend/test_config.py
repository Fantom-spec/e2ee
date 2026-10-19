"""Configuration must fail safe: unsafe or missing settings stop startup."""

import unittest

from app.config import MIN_SECRET_LEN, ConfigError, load_settings

SECRET = "unit-test-only-secret-not-for-real-use-0123456789"
GOOD = {
    "SECURECHAT_ENV": "development",
    "SECURECHAT_SECRET_KEY": SECRET,
    "SECURECHAT_ALLOWED_ORIGINS": "http://localhost:5173",
}


def env(**overrides: str) -> dict[str, str]:
    merged = dict(GOOD)
    merged.update(overrides)
    return {k: v for k, v in merged.items() if v is not None}


class ConfigTests(unittest.TestCase):
    def test_valid_development_config_loads(self) -> None:
        s = load_settings(env())
        self.assertTrue(s.is_development)
        self.assertEqual(s.allowed_origins, ("http://localhost:5173",))
        self.assertEqual(s.max_envelope_bytes, 65_536)

    def test_missing_secret_is_rejected(self) -> None:
        e = env()
        del e["SECURECHAT_SECRET_KEY"]
        with self.assertRaises(ConfigError):
            load_settings(e)

    def test_short_secret_is_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            load_settings(env(SECURECHAT_SECRET_KEY="a" * (MIN_SECRET_LEN - 1)))

    def test_placeholder_secret_is_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            load_settings(env(SECURECHAT_SECRET_KEY="change-me-" + "x" * 40))

    def test_wildcard_origin_is_rejected(self) -> None:
        for bad in ("*", "https://*.example.com", "http://localhost:5173,*"):
            with self.subTest(origin=bad), self.assertRaises(ConfigError):
                load_settings(env(SECURECHAT_ALLOWED_ORIGINS=bad))

    def test_missing_or_empty_origins_are_rejected(self) -> None:
        for value in ("", " , "):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                load_settings(env(SECURECHAT_ALLOWED_ORIGINS=value))

    def test_origin_with_path_is_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            load_settings(env(SECURECHAT_ALLOWED_ORIGINS="https://a.example/app"))

    def test_default_env_is_production_and_requires_https(self) -> None:
        e = env(SECURECHAT_ALLOWED_ORIGINS="http://localhost:5173")
        del e["SECURECHAT_ENV"]
        with self.assertRaises(ConfigError):
            load_settings(e)
        e["SECURECHAT_ALLOWED_ORIGINS"] = "https://chat.example.com/"
        s = load_settings(e)
        self.assertEqual(s.env, "production")
        self.assertFalse(s.is_development)
        self.assertEqual(s.allowed_origins, ("https://chat.example.com",))

    def test_unknown_env_is_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            load_settings(env(SECURECHAT_ENV="staging"))

    def test_non_integer_and_out_of_range_numbers_are_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            load_settings(env(SECURECHAT_SESSION_TTL_SECONDS="abc"))
        with self.assertRaises(ConfigError):
            load_settings(env(SECURECHAT_MAX_ENVELOPE_BYTES="10"))

    def test_stage2_defaults(self) -> None:
        s = load_settings(env())
        self.assertFalse(s.trust_cf_connecting_ip)  # off unless explicitly enabled
        self.assertEqual((s.scrypt_log_n, s.max_connections_per_user, s.max_pending_per_recipient),
                         (17, 5, 1_000))

    def test_weak_scrypt_cost_rejected_in_production_only(self) -> None:
        prod = env(SECURECHAT_ALLOWED_ORIGINS="https://chat.example.com", SECURECHAT_SCRYPT_LOG_N="12")
        del prod["SECURECHAT_ENV"]
        with self.assertRaises(ConfigError):
            load_settings(prod)
        self.assertEqual(load_settings(env(SECURECHAT_SCRYPT_LOG_N="12")).scrypt_log_n, 12)

    def test_boolean_setting_parsing(self) -> None:
        self.assertTrue(load_settings(env(SECURECHAT_TRUST_CF_CONNECTING_IP="true")).trust_cf_connecting_ip)
        self.assertFalse(load_settings(env(SECURECHAT_TRUST_CF_CONNECTING_IP="no")).trust_cf_connecting_ip)
        with self.assertRaises(ConfigError):
            load_settings(env(SECURECHAT_TRUST_CF_CONNECTING_IP="maybe"))

    def test_secret_not_in_repr(self) -> None:
        self.assertNotIn(SECRET, repr(load_settings(env())))


if __name__ == "__main__":
    unittest.main()
