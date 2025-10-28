print("LOADED app.routes")

from flask import Blueprint, request, jsonify
from sqlalchemy import text
from .extensions import db

bp = Blueprint("api", __name__)

@bp.get("/")
def home():
    return jsonify(ok=True, service="backend")

@bp.get("/db-ping")
def db_ping():
    db.session.execute(text("SELECT 1"))
    return jsonify(ok=True)

# show all salons
@bp.get("/salons")
def list_salons():
    q = text("""
        SELECT s.salon_id, s.name, s.city, s.state,
               COALESCE(ROUND(AVG(r.rating),2), 0) AS avg_rating,
               COUNT(r.review_id) AS review_count
        FROM salons s
        LEFT JOIN reviews r ON r.salon_id = s.salon_id
        GROUP BY s.salon_id, s.name, s.city, s.state
        ORDER BY s.name
        LIMIT 200
    """)
    rows = db.session.execute(q).mappings().all()
    return jsonify(list(rows)), 200

# reviews for one salon
@bp.get("/salons/<int:salon_id>/reviews")
def salon_reviews(salon_id: int):
    page = max(int(request.args.get("page", 1)), 1)
    size = min(max(int(request.args.get("size", 10)), 1), 50)
    q = text("""
        SELECT r.review_id, r.rating, r.comment, r.created_at,
               u.name AS reviewer
        FROM reviews r
        JOIN users u ON u.user_id = r.user_id
        WHERE r.salon_id = :sid
        ORDER BY r.created_at DESC
        LIMIT :limit OFFSET :offset
    """)
    rows = db.session.execute(q, {
        "sid": salon_id,
        "limit": size,
        "offset": (page - 1) * size
    }).mappings().all()
    return jsonify(list(rows)), 200
