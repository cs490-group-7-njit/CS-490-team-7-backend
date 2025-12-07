import json
import pytest
from datetime import datetime, timezone

from app.models import Salon 


def test_update_salon_failure_not_found(client):
    """Test updating a salon ID that does not exist (404 Not Found)."""
    non_existent_id = 999
    update_data = {"name": "Should Fail"}
    
    response = client.put(f"/salons/{non_existent_id}", json=update_data)
    response_data = json.loads(response.data)
    
    assert response.status_code == 404
    assert response_data["error"] == "not_found"
    assert f"salon_id {non_existent_id} does not exist" in response_data["message"]