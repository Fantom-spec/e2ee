"""HTTP-level tests. Require fastapi + httpx (backend/requirements-dev.txt).

If those packages are missing the tests are reported as SKIPPED, never passed.
"""

import tempfile
import unittest
from pathlib import Path

from app.config import load_settings

try:
    from fastapi.testclient import TestClient

    from app.main import create_app

    HAVE_WEB = True
except ImportError:  # pragma: no cover - depends on the environment
    HAVE_WEB = False

SECRET = "unit-test-only-secret-not-for-real-use-0123456789"
ALLOWED = "http://localhost:5173"


@unittest.skipUnless(HAVE_WEB, "fastapi/httpx not installed in this environment")
class HealthTests(unittest.TestCase):
    def make_client(self, env: str = "development") -> "TestClient":
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        settings = load_settings({
            "SECURECHAT_ENV": env,
            "SECURECHAT_SECRET_KEY": SECRET,
            "SECURECHAT_ALLOWED_ORIGINS": ALLOWED if env == "development" else "https://chat.example.com",
            "SECURECHAT_DB_PATH": str(Path(tmp.name) / "t.sqlite3"),
        })
        client = TestClient(create_app(settings))
        client.__enter__()  # runs lifespan (initialises the database)
        self.addCleanup(client.__exit__, None, None, None)
        return client

    def test_health_ok_and_database_created(self) -> None:
        client = self.make_client()
        r = client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "ok")
        self.assertTrue(Path(client.app.state.settings.db_path).exists())

    def test_cors_allows_only_configured_origin(self) -> None:
        client = self.make_client()
        ok = client.get("/api/health", headers={"Origin": ALLOWED})
        self.assertEqual(ok.headers.get("access-control-allow-origin"), ALLOWED)
        evil = client.get("/api/health", headers={"Origin": "https://evil.example"})
        self.assertNotIn("access-control-allow-origin", evil.headers)

    def test_api_docs_disabled_in_production(self) -> None:
        client = self.make_client(env="production")
        self.assertEqual(client.get("/api/docs").status_code, 404)
        self.assertEqual(client.get("/api/openapi.json").status_code, 404)

    def test_api_docs_enabled_in_development(self) -> None:
        client = self.make_client(env="development")
        self.assertEqual(client.get("/api/openapi.json").status_code, 200)


if __name__ == "__main__":
    unittest.main()
