from fastapi.testclient import TestClient

from cloud.app.main import app


def test_liveness_does_not_require_external_services():
    # Do not enter TestClient as a context manager: startup dependencies are
    # intentionally not required for the liveness endpoint.
    response = TestClient(app).get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
