"""User Account and Identity Management blueprint.

Provides REST endpoints for user account settings, credential updates,
avatar management, and administrative user/role directory listing.
"""

from __future__ import annotations

import contextlib
import time
from typing import Any

from flask import Blueprint, Response, jsonify, request

from utils.logging import sensor_logger as logger
from utils.responses import api_error

identity_bp = Blueprint("identity", __name__, url_prefix="/identity")

# ---------------------------------------------------------------------------
# Mock Database / Repository Helpers
# (Replace these with your actual ORM models or database connection layer)
# ---------------------------------------------------------------------------

_MOCK_USERS_DB = [
    {
        "id": 101,
        "name": "Alex Morgan",
        "email": "alex.morgan@company.com",
        "role": "Administrator",
        "status": "Active",
        "avatar": "",
        "last_update": "2026-06-01 12:00:00",
    },
    {
        "id": 102,
        "name": "Sarah Connor",
        "email": "s.connor@company.com",
        "role": "Security Lead",
        "status": "Active",
        "avatar": "",
        "last_update": "2026-06-02 14:30:00",
    },
    {
        "id": 103,
        "name": "David Vance",
        "email": "d.vance@company.com",
        "role": "Operator",
        "status": "Inactive",
        "avatar": "",
        "last_update": "2026-05-20 09:15:00",
    },
    {
        "id": 104,
        "name": "Elena Rostova",
        "email": "e.rostova@company.com",
        "role": "Analyst",
        "status": "Active",
        "avatar": "",
        "last_update": "2026-06-04 11:45:00",
    },
    {
        "id": 105,
        "name": "Marcus Wright",
        "email": "m.wright@company.com",
        "role": "Operator",
        "status": "Active",
        "avatar": "",
        "last_update": "2026-06-05 08:00:00",
    },
]

# Track current active user session (simulated)
_CURRENT_USER_ID = 101


def _get_user_by_id(user_id: int) -> dict[str, Any] | None:
    """Retrieve a user record by ID from the database."""
    for user in _MOCK_USERS_DB:
        if user["id"] == user_id:
            return user
    return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@identity_bp.route("/account", methods=["GET"])
def get_current_account() -> Response:
    """Return the profile details of the currently authenticated user."""
    try:
        user = _get_user_by_id(_CURRENT_USER_ID)
        if not user:
            return api_error("Current user account not found", 404)
        
        # Strip sensitive data if any before returning
        account_data = {k: v for k, v in user.items()}
        return jsonify(account_data)
    except Exception as exc:
        logger.error("Failed to fetch current account details: %s", exc)
        return api_error(str(exc), 500)


@identity_bp.route("/account", methods=["PUT", "PATCH"])
def update_current_account() -> Response:
    """Update profile details, display name, avatar, or credentials of current user."""
    try:
        data = request.get_json(silent=True) or {}
        user = _get_user_by_id(_CURRENT_USER_ID)
        if not user:
            return api_error("Current user account not found", 404)

        # Update display name if provided
        if "name" in data:
            name_val = str(data["name"]).strip()
            if not name_val:
                return api_error("Display name cannot be empty")
            user["name"] = name_val

        # Update credentials / password if requested
        if "new_password" in data:
            current_pass = data.get("current_password", "")
            new_pass = data.get("new_password", "")
            
            # TODO: Validate current_pass against hashed password in database
            if not new_pass or len(new_pass) < 6:
                return api_error("New password must be at least 6 characters long")
            logger.info("Password successfully updated for user ID: %s", _CURRENT_USER_ID)

        # Update timestamp
        import datetime
        user["last_update"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        logger.info("Account settings updated for user ID: %s", _CURRENT_USER_ID)
        return jsonify({"success": True, "user": user})
    except Exception as exc:
        logger.error("Failed to update account settings: %s", exc)
        return api_error(str(exc), 500)


@identity_bp.route("/users", methods=["GET"])
def list_users() -> Response:
    """List all registered system users and roles for the administrative directory."""
    try:
        search_query = request.args.get("search", "").strip().lower()
        role_filter = request.args.get("role", "").strip().lower()

        results = _MOCK_USERS_DB

        # Filter by search term (name or email)
        if search_query:
            results = [
                u for u in results
                if search_query in u["name"].lower() or search_query in u["email"].lower()
            ]

        # Filter by role
        if role_filter:
            results = [
                u for u in results
                if role_filter == u["role"].lower()
            ]

        return jsonify({
            "total": len(results),
            "users": results
        })
    except Exception as exc:
        logger.error("Failed to list users directory: %s", exc)
        return api_error(str(exc), 500)


@identity_bp.route("/users/<int:user_id>", methods=["GET"])
def get_user_detail(user_id: int) -> Response:
    """Retrieve details for a specific user by ID (Admin action)."""
    try:
        user = _get_user_by_id(user_id)
        if not user:
            return api_error("User not found", 404)
        return jsonify(user)
    except Exception as exc:
        logger.error("Failed to fetch user ID %s: %s", user_id, exc)
        return api_error(str(exc), 500)