import pytest
from datetime import datetime, timedelta
from app.models import db, Salon, User 


@pytest.fixture
def setup_salons(app):  # CHANGED: 'app_context' replaced with 'app'
    """
    Sets up a collection of published and unpublished salons with distinct
    properties for testing filtering, sorting, and publication status.
    """
    # Ensure database operations run within the application context
    with app.app_context():
        vendor_a = User(name="Vendor A", email="vendor.a@example.com", role="vendor")
        vendor_b = User(name="Vendor B", email="vendor.b@example.com", role="vendor")
        db.session.add_all([vendor_a, vendor_b])
        db.session.flush()

        # 2. Create Salons (Published & Unpublished)
        now = datetime.utcnow()
        salons = [
            # ID 1: Published, default sort (latest created_at)
            Salon(
                vendor_id=vendor_a.user_id,
                name="Zebra Stripes Salon",
                city="New York",
                business_type="Haircut",
                is_published=True,
                created_at=now - timedelta(minutes=1),
            ),
            # ID 2: Published, different city/type, older created_at
            Salon(
                vendor_id=vendor_a.user_id,
                name="Artistic Fades",
                city="Miami",
                business_type="Barber",
                is_published=True,
                created_at=now - timedelta(minutes=5),
            ),
            # ID 3: Published, for query/name sorting test
            Salon(
                vendor_id=vendor_b.user_id,
                name="Great Clips",
                city="New York",
                business_type="Haircut",
                is_published=True,
                created_at=now - timedelta(minutes=3),
            ),
            # ID 4: UNPUBLISHED - Should NEVER appear in the results
            Salon(
                vendor_id=vendor_b.user_id,
                name="Secret Spa",
                city="Chicago",
                business_type="Spa",
                is_published=False,
                created_at=now - timedelta(minutes=2),
            ),
            # ID 5: Published, for city/business_type filter test
            Salon(
                vendor_id=vendor_a.user_id,
                name="Miami Hair King",
                city="Miami",
                business_type="Haircut",
                is_published=True,
                created_at=now - timedelta(minutes=4),
            ),
        ]
        db.session.add_all(salons)
        db.session.commit()
        return salons


# --- Test Cases ---
def test_list_salons_success_no_params(client, setup_salons):
    """Tests the default behavior (no parameters): published, sorted by created_at DESC."""
    response = client.get("/salons")
    assert response.status_code == 200
    data = response.get_json()

    assert len(data['salons']) == 4
    assert data['pagination']['total'] == 4

    salon_names = [s['name'] for s in data['salons']]
    assert "Secret Spa" not in salon_names

    assert data['salons'][0]['name'] == "Zebra Stripes Salon"
    assert data['salons'][-1]['name'] == "Artistic Fades"

    assert 'vendor' in data['salons'][0]
    assert 'email' in data['salons'][0]['vendor']
    assert data['salons'][0]['vendor']['role'] == 'vendor'

def test_list_salons_filter_by_query_partial_case_insensitive(client, setup_salons):
    """Tests filtering by 'query' parameter (partial, case-insensitive match on name)."""
    response = client.get("/salons?query=clip")
    assert response.status_code == 200
    data = response.get_json()

    assert data['pagination']['total'] == 1
    assert data['salons'][0]['name'] == "Great Clips"
    assert data['filters']['query'] == "clip"

def test_list_salons_filter_by_city_case_insensitive(client, setup_salons):
    """Tests filtering by 'city' parameter (exact match, case-insensitive)."""
    response = client.get("/salons?city=mIaMi")
    assert response.status_code == 200
    data = response.get_json()

    assert data['pagination']['total'] == 2
    salon_names = {s['name'] for s in data['salons']}
    assert "Artistic Fades" in salon_names
    assert "Miami Hair King" in salon_names
    assert "Zebra Stripes Salon" not in salon_names

def test_list_salons_filter_by_business_type_case_insensitive(client, setup_salons):
    """Tests filtering by 'business_type' parameter (exact match, case-insensitive)."""
    response = client.get("/salons?business_type=bArBeR")
    assert response.status_code == 200
    data = response.get_json()

    assert data['pagination']['total'] == 1
    assert data['salons'][0]['name'] == "Artistic Fades"
    assert data['filters']['business_type'] == "bArBeR"

def test_list_salons_combined_filters(client, setup_salons):
    """Tests combining multiple filters."""
    response = client.get("/salons?city=New York&business_type=Haircut")
    assert response.status_code == 200
    data = response.get_json()

    assert data['pagination']['total'] == 2
    salon_names = {s['name'] for s in data['salons']}
    assert "Zebra Stripes Salon" in salon_names
    assert "Great Clips" in salon_names

def test_list_salons_sort_by_name_asc(client, setup_salons):
    """Tests sorting by name ascending."""
    response = client.get("/salons?sort=name&order=asc")
    assert response.status_code == 200
    data = response.get_json()

    assert data['pagination']['total'] == 4
    assert data['salons'][0]['name'] == "Artistic Fades"
    assert data['salons'][-1]['name'] == "Zebra Stripes Salon"
    assert data['filters']['sort'] == "name"
    assert data['filters']['order'] == "asc"

def test_list_salons_sort_by_name_desc(client, setup_salons):
    """Tests sorting by name descending."""
    response = client.get("/salons?sort=name&order=desc")
    assert response.status_code == 200
    data = response.get_json()

    assert data['pagination']['total'] == 4
    assert data['salons'][0]['name'] == "Zebra Stripes Salon"
    assert data['salons'][-1]['name'] == "Artistic Fades"

def test_list_salons_pagination(client, setup_salons):
    """Tests pagination with a limit of 2 and page 2."""
    response = client.get("/salons?limit=2&page=2&sort=name&order=asc")
    assert response.status_code == 200
    data = response.get_json()

    assert data['pagination']['total'] == 4
    assert data['pagination']['limit'] == 2
    assert data['pagination']['page'] == 2
    assert data['pagination']['pages'] == 2
    assert len(data['salons']) == 2

    assert data['salons'][0]['name'] == "Miami Hair King"
    assert data['salons'][1]['name'] == "Zebra Stripes Salon"

def test_list_salons_pagination_invalid_params(client, setup_salons):
    """Tests handling of invalid pagination parameters."""
    response = client.get("/salons?limit=100")
    assert response.status_code == 200
    assert response.get_json()['pagination']['limit'] == 50

    response = client.get("/salons?page=abc")
    assert response.status_code == 400
    assert response.get_json()['error'] == "invalid_parameters"
    
    response = client.get("/salons?limit=xyz")
    assert response.status_code == 400
    assert response.get_json()['error'] == "invalid_parameters"
    
def test_list_salons_pagination_page_out_of_bounds(client, setup_salons):
    """Tests request for a page number that exceeds total pages."""
    response = client.get("/salons?page=5")
    assert response.status_code == 200
    data = response.get_json()

    assert len(data['salons']) == 0
    assert data['pagination']['total'] == 4
    assert data['pagination']['page'] == 5 

def test_list_salons_invalid_sort_param(client, setup_salons):
    """Tests that an invalid sort parameter defaults to 'created_at' and 'desc'."""
    names_asc = ["Artistic Fades", "Great Clips", "Miami Hair King", "Zebra Stripes Salon"]
    
    response = client.get("/salons?sort=invalid_field&order=up")
    assert response.status_code == 200
    data = response.get_json()

    assert data['filters']['sort'] == "created_at"
    assert data['filters']['order'] == "desc"
    
    assert data['salons'][0]['name'] == "Zebra Stripes Salon"