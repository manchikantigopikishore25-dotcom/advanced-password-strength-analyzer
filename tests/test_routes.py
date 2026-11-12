"""
Integration tests for Flask Routes and API endpoints.
Verifies HTTP status codes, security headers, zero-logging assertion, and error handlers.
"""
import pytest
from app import create_app
from config.config import TestingConfig


@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.test_client() as test_client:
        yield test_client


def test_index_route(client):
    """GET / should render the dashboard with status 200."""
    res = client.get("/")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Advanced Password Strength Analyzer" in html
    assert "In-Memory Processing Only" in html


def test_security_headers(client):
    """All HTTP responses must enforce modern defense-in-depth security headers."""
    res = client.get("/")
    headers = res.headers
    assert "Content-Security-Policy" in headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert "no-store" in headers.get("Cache-Control", "")


def test_api_health(client):
    """GET /api/health returns healthy telemetry."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert data["privacy_guarantee"] == "zero_credential_retention"


def test_api_analyze_valid(client):
    """POST /api/analyze computes metrics and NEVER returns original password."""
    res = client.post("/api/analyze", json={"password": "TestValidPassword123!"})
    assert res.status_code == 200
    data = res.get_json()
    assert "score" in data
    assert "strength" in data
    assert "entropy_bits" in data
    assert "recommendations" in data
    assert "password" not in data


def test_api_analyze_empty(client):
    """POST /api/analyze with empty password returns score 0."""
    res = client.post("/api/analyze", json={"password": ""})
    assert res.status_code == 200
    data = res.get_json()
    assert data["score"] == 0
    assert data["strength"] == "Very Weak"


def test_api_analyze_invalid_type(client):
    """POST /api/analyze with non-string payload returns 400 Bad Request."""
    res = client.post("/api/analyze", json={"password": 12345})
    assert res.status_code == 400
    data = res.get_json()
    assert "error" in data


def test_api_analyze_length_limit(client):
    """POST /api/analyze exceeding max length returns 400."""
    giant_string = "A" * 300
    res = client.post("/api/analyze", json={"password": giant_string})
    assert res.status_code == 400
    data = res.get_json()
    assert "exceeds maximum allowable length" in data["error"]


def test_api_generate_random(client):
    """POST /api/generate produces cryptographically secure password."""
    res = client.post("/api/generate", json={
        "mode": "random",
        "length": 22,
        "use_upper": True,
        "use_lower": True,
        "use_digits": True,
        "use_special": True
    })
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["password"]) == 22


def test_api_generate_passphrase(client):
    """POST /api/generate produces Diceware passphrase in passphrase mode."""
    res = client.post("/api/generate", json={
        "mode": "passphrase",
        "word_count": 5,
        "separator": "-"
    })
    assert res.status_code == 200
    data = res.get_json()
    words = data["passphrase"].split("-")
    assert len(words) == 5


def test_api_generate_invalid_params(client):
    """POST /api/generate with invalid params returns 400."""
    res = client.post("/api/generate", json={
        "mode": "random",
        "length": 4
    })
    assert res.status_code == 400
    assert "error" in res.get_json()


def test_api_history_and_clear(client):
    """GET /api/history returns non-sensitive metadata; clear purges it."""
    # Run an analysis to populate telemetry
    client.post("/api/analyze", json={"password": "SamplePassword123!"})

    res = client.get("/api/history")
    assert res.status_code == 200
    data = res.get_json()
    assert "history" in data
    assert "statistics" in data

    # Verify history contains NO passwords
    for entry in data["history"]:
        assert "password" not in entry
        assert "hash" not in entry

    # Clear history
    res_clear = client.post("/api/history/clear")
    assert res_clear.status_code == 200

    # Verify cleared
    res_after = client.get("/api/history")
    assert len(res_after.get_json()["history"]) == 0


def test_404_handler(client):
    """Invalid routes return 404 with proper JSON or HTML."""
    res = client.get("/api/nonexistent_endpoint")
    assert res.status_code == 404
    assert res.get_json()["error"] == "API endpoint not found."
