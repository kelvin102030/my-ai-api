import tempfile
import unittest
from unittest.mock import patch
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


    def test_chat_rejects_missing_malformed_and_invalid_keys(self):
        cases = [
            {},
            {"Authorization": "Basic abc123"},
            {"Authorization": "Bearer definitely-not-a-valid-key"},
        ]

        for headers in cases:
            with self.subTest(headers=headers):
                response = self.client.post(
                    "/v1/chat/completions",
                    headers=headers,
                    json={"messages": [{"role": "user", "content": "Hello"}]},
                )
                self.assertEqual(response.status_code, 401)

    def test_user_cannot_revoke_another_users_key(self):
        self.register_and_login()
        response = self.client.post(
            "/api/keys", json={"name": "Owner key"}
        )
        self.assertEqual(response.status_code, 201, response.json)
        key_id = response.json["id"]

        self.client.post("/api/logout")

        other_email = "another-developer@example.com"
        response = self.client.post(
            "/api/register",
            json={"email": other_email, "password": "another-test-password"},
        )
        self.assertEqual(response.status_code, 201, response.json)
        response = self.client.post(
            "/api/login",
            json={"email": other_email, "password": "another-test-password"},
        )
        self.assertEqual(response.status_code, 200, response.json)

        response = self.client.post(f"/api/keys/{key_id}/revoke")
        self.assertEqual(response.status_code, 404)

        self.client.post("/api/logout")
        response = self.client.post(
            "/api/login",
            json={"email": self.email, "password": self.password},
        )
        self.assertEqual(response.status_code, 200, response.json)

        with api.connect_db() as db:
            row = db.execute(
                "SELECT revoked FROM api_keys WHERE id = ?", (key_id,)
            ).fetchone()
        self.assertEqual(row["revoked"], 0)


    def test_rate_limit_allows_30_requests_and_rejects_31st(self):
        self.register_and_login()
        response = self.client.post(
            "/api/keys", json={"name": "Rate-limit test"}
        )
        self.assertEqual(response.status_code, 201, response.json)
        token = response.json["api_key"]
        headers = {"Authorization": f"Bearer {token}"}
        payload = {"messages": [{"role": "user", "content": "Hello"}]}

        # Keep the test independent of real environment configuration and time.
        with patch.dict(api.os.environ, {"GEMINI_API_KEY": ""}), \
             patch.object(api.time, "time", return_value=1800000000):
            for attempt in range(30):
                response = self.client.post(
                    "/v1/chat/completions",
                    headers=headers,
                    json=payload,
                )
                self.assertEqual(
                    response.status_code, 503,
                    f"Request {attempt + 1} returned {response.status_code}: "
                    f"{response.json}",
                )

            response = self.client.post(
                "/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            self.assertEqual(response.status_code, 429, response.json)
            self.assertIn("Rate limit exceeded", response.json["error"])


if __name__ == "__main__":
    unittest.main()
