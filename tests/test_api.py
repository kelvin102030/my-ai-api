import tempfile
import unittest
from pathlib import Path

import app.main as api


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = api.DB_PATH
        api.DB_PATH = Path(self.temp.name) / "test.db"
        api.initialize_db()
        self.client = api.app.test_client()
        self.email = "developer@example.com"
        self.password = "test-password-123"

    def tearDown(self):
        api.DB_PATH = self.old_db
        self.temp.cleanup()

    def register_and_login(self):
        response = self.client.post(
            "/api/register",
            json={"email": self.email, "password": self.password},
        )
        self.assertEqual(response.status_code, 201, response.json)
        response = self.client.post(
            "/api/login",
            json={"email": self.email, "password": self.password},
        )
        self.assertEqual(response.status_code, 200, response.json)

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")

    def test_register_and_login(self):
        self.register_and_login()

    def test_duplicate_registration_rejected(self):
        self.register_and_login()
        response = self.client.post(
            "/api/register",
            json={"email": self.email, "password": self.password},
        )
        self.assertEqual(response.status_code, 409)

    def test_key_creation_and_authenticated_request(self):
        self.register_and_login()
        response = self.client.post(
            "/api/keys", json={"name": "Test key"}
        )
        self.assertEqual(response.status_code, 201, response.json)
        token = response.json["api_key"]
        key_id = response.json["id"]

        response = self.client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={"messages": [{"role": "user", "content": "Hello"}]},
        )
        self.assertEqual(response.status_code, 503)
        self.assertIn("No AI model provider", response.json["error"])

        response = self.client.post(
            f"/api/keys/{key_id}/revoke"
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={"messages": [{"role": "user", "content": "Hello"}]},
        )
        self.assertEqual(response.status_code, 401)

    def test_usage_requires_login(self):
        response = self.client.get("/api/usage")
        self.assertEqual(response.status_code, 401)

    def test_usage_returns_account_totals(self):
        self.register_and_login()

        with api.connect_db() as db:
            db.execute("""
                INSERT INTO usage (
                    user_id, key_id, endpoint,
                    prompt_tokens, completion_tokens, total_tokens
                )
                SELECT id, 1, '/v1/chat/completions', 10, 5, 15
                FROM users WHERE email = ?
            """, (self.email,))

        response = self.client.get("/api/usage")
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json["requests"], 1)
        self.assertEqual(response.json["prompt_tokens"], 10)
        self.assertEqual(response.json["completion_tokens"], 5)
        self.assertEqual(response.json["total_tokens"], 15)

    def test_keys_require_login(self):
        response = self.client.post("/api/keys", json={"name": "Test"})
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
