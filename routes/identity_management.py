"""User Account and Identity Management blueprint.

Provides REST endpoints for real-time user account settings, credential updates,
and administrative user/role directory querying directly from the SQLite database
using the global application database utility.
"""

from __future__ import annotations

import sqlite3

from flask import Blueprint, Response, jsonify, request
from werkzeug.security import generate_password_hash

from utils.database import get_db
from utils.logging import sensor_logger as logger
from utils.responses import api_error

identity_bp = Blueprint("identity", __name__, url_prefix="/identity")


def _get_current_user_id() -> int:
    """Return the currently authenticated user ID (from request/session context)."""
    return request.headers.get("X-User-ID", type=int) or 1


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@identity_bp.route("/account", methods=["GET"])
def get_current_account() -> Response:
    """Return profile details of the currently authenticated user directly from the DB."""
    current_user_id = _get_current_user_id()

    try:
        with get_db() as conn:
            user = conn.execute(
                """
                SELECT id, username, role, created_at, must_change_password
                FROM users
                WHERE id = ?
                """,
                (current_user_id,),
            ).fetchone()

        if not user:
            return api_error("User account not found in database", 404)

        return jsonify(
            {
                "id": user["id"],
                "name": user["username"],
                "role": user["role"],
                "status": "Active" if user["must_change_password"] == 0 else "Pending Password Change",
                "last_update": user["created_at"],
            }
        )
    except sqlite3.Error as exc:
        logger.error("Database error fetching account (ID %s): %s", current_user_id, exc)
        return api_error("Database query failed", 500)
    except Exception as exc:
        logger.error("Unexpected error fetching account: %s", exc)
        return api_error(str(exc), 500)


@identity_bp.route("/account", methods=["PUT", "PATCH"])
def update_current_account() -> Response:
    """Update profile details, username, or credentials for the current user in DB."""
    current_user_id = _get_current_user_id()
    data = request.get_json(silent=True) or {}

    new_username = str(data.get("name", "")).strip() if "name" in data else None
    current_password = data.get("current_password", "")
    new_password = str(data.get("new_password", "")).strip() if "new_password" in data else None

    if new_username == "":
        return api_error("Username cannot be empty", 400)

    if new_password is not None and len(new_password) < 6:
        return api_error("New password must be at least 6 characters long", 400)

    try:
        with get_db() as conn:
            # Verify user exists and fetch current password hash
            user = conn.execute(
                "SELECT id, password_hash FROM users WHERE id = ?",
                (current_user_id,)
            ).fetchone()

            if not user:
                return api_error("User account not found in database", 404)

            # Si el usuario quiere cambiar la contraseña, validar obligatoriamente la actual
            if new_password:
                if not current_password:
                    return api_error("Current password is required to set a new password", 400)

                from werkzeug.security import check_password_hash
                if not check_password_hash(user["password_hash"], current_password):
                    return api_error("Current password is incorrect", 401)

            # Update username if supplied
            if new_username:
                conn.execute(
                    "UPDATE users SET username = ? WHERE id = ?",
                    (new_username, current_user_id),
                )

            # Update password hash if supplied
            if new_password:
                password_hash = generate_password_hash(new_password)
                conn.execute(
                    """
                    UPDATE users
                    SET password_hash = ?, must_change_password = 0
                    WHERE id = ?
                    """,
                    (password_hash, current_user_id),
                )

            conn.commit()

        logger.info("Successfully updated account details for user ID %s", current_user_id)
        return jsonify({"success": True, "message": "Account updated successfully"})

    except sqlite3.IntegrityError:
        logger.warning("Username '%s' already exists in database", new_username)
        return api_error("Username is already taken", 409)
    except sqlite3.Error as exc:
        logger.error("Database error updating user ID %s: %s", current_user_id, exc)
        return api_error("Database update failed", 500)
    except Exception as exc:
        logger.error("Unexpected error updating account: %s", exc)
        return api_error(str(exc), 500)

@identity_bp.route("/users", methods=["GET"])
def list_users() -> Response:
    """List all registered users directly from the SQLite database."""
    search_query = request.args.get("search", "").strip()

    try:
        with get_db() as conn:
            if search_query:
                query = """
                    SELECT id, username, role, created_at, must_change_password
                    FROM users
                    WHERE LOWER(username) LIKE LOWER(?)
                    ORDER BY id ASC
                """
                rows = conn.execute(query, (f"%{search_query}%",)).fetchall()
            else:
                query = """
                    SELECT id, username, role, created_at, must_change_password
                    FROM users
                    ORDER BY id ASC
                """
                rows = conn.execute(query).fetchall()

        results = []
        for row in rows:
            results.append(
                {
                    "id": row["id"],
                    "name": row["username"],
                    "role": row["role"],
                    "status": "Active" if row["must_change_password"] == 0 else "Pending Password Change",
                    "last_update": row["created_at"],
                }
            )

        return jsonify({"total": len(results), "users": results})

    except sqlite3.Error as exc:
        logger.error("Database error listing users: %s", exc)
        return api_error("Database query failed", 500)
    except Exception as exc:
        logger.error("Unexpected error listing users: %s", exc)
        return api_error(str(exc), 500)


@identity_bp.route("/users/<int:user_id>", methods=["GET"])
def get_user_detail(user_id: int) -> Response:
    """Retrieve specific user details by ID directly from SQLite."""
    try:
        with get_db() as conn:
            user = conn.execute(
                """
                SELECT id, username, role, created_at, must_change_password
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            ).fetchone()

        if not user:
            return api_error("User not found", 404)

        return jsonify(
            {
                "id": user["id"],
                "name": user["username"],
                "role": user["role"],
                "status": "Active" if user["must_change_password"] == 0 else "Pending Password Change",
                "last_update": user["created_at"],
            }
        )
    except sqlite3.Error as exc:
        logger.error("Database error fetching user ID %s: %s", user_id, exc)
        return api_error("Database query failed", 500)
    except Exception as exc:
        logger.error("Unexpected error fetching user ID %s: %s", user_id, exc)
        return api_error(str(exc), 500)
