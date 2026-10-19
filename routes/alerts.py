"""Alerting API endpoints."""

from __future__ import annotations

from flask import Blueprint, Response, request

from utils import alert_channels, watchlists
from utils.alerts import get_alert_manager
from utils.responses import api_error, api_success
from utils.sse import sse_stream_fanout

alerts_bp = Blueprint("alerts", __name__, url_prefix="/alerts")


@alerts_bp.route("/rules", methods=["GET"])
def list_rules():
    manager = get_alert_manager()
    include_disabled = request.args.get("all") in ("1", "true", "yes")
    return api_success(data={"rules": manager.list_rules(include_disabled=include_disabled)})


@alerts_bp.route("/rules", methods=["POST"])
def create_rule():
    data = request.get_json() or {}
    if not isinstance(data.get("match", {}), dict):
        return api_error("match must be a JSON object", 400)

    manager = get_alert_manager()
    rule_id = manager.add_rule(data)
    return api_success(data={"rule_id": rule_id})


@alerts_bp.route("/rules/<int:rule_id>", methods=["PUT", "PATCH"])
def update_rule(rule_id: int):
    data = request.get_json() or {}
    manager = get_alert_manager()
    ok = manager.update_rule(rule_id, data)
    if not ok:
        return api_error("Rule not found or no changes", 404)
    return api_success()


@alerts_bp.route("/rules/<int:rule_id>", methods=["DELETE"])
def delete_rule(rule_id: int):
    manager = get_alert_manager()
    ok = manager.delete_rule(rule_id)
    if not ok:
        return api_error("Rule not found", 404)
    return api_success()


@alerts_bp.route("/events", methods=["GET"])
def list_events():
    manager = get_alert_manager()
    limit = request.args.get("limit", default=100, type=int)
    mode = request.args.get("mode")
    severity = request.args.get("severity")
    events = manager.list_events(limit=limit, mode=mode, severity=severity)
    return api_success(data={"events": events})


@alerts_bp.route("/stream", methods=["GET"])
def stream_alerts() -> Response:
    manager = get_alert_manager()
    response = Response(
        sse_stream_fanout(
            source_queue=manager._queue,
            channel_key="alerts",
            timeout=1.0,
            keepalive_interval=30.0,
        ),
        mimetype="text/event-stream",
    )
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Connection"] = "keep-alive"
    return response


# ----------------------------------------------------------------------
# Limits
# ----------------------------------------------------------------------


@alerts_bp.route("/limits", methods=["GET"])
def get_limits():
    return api_success(data={"limits": get_alert_manager().get_limits()})


@alerts_bp.route("/limits", methods=["PUT", "PATCH"])
def update_limits():
    try:
        limits = get_alert_manager().update_limits(request.get_json() or {})
    except (TypeError, ValueError) as e:
        return api_error(str(e), 400)
    return api_success(data={"limits": limits})


# ----------------------------------------------------------------------
# Watchlists
# ----------------------------------------------------------------------


@alerts_bp.route("/watchlists", methods=["GET"])
def list_watchlists():
    return api_success(data={"watchlists": [w.to_dict() for w in watchlists.list_watchlists()]})


@alerts_bp.route("/watchlists", methods=["POST"])
def create_watchlist():
    try:
        watchlist_id = watchlists.create(request.get_json() or {})
    except ValueError as e:
        return api_error(str(e), 400)
    return api_success(data={"watchlist_id": watchlist_id})


@alerts_bp.route("/watchlists/<int:watchlist_id>", methods=["PUT", "PATCH"])
def update_watchlist(watchlist_id: int):
    try:
        ok = watchlists.update(watchlist_id, request.get_json() or {})
    except ValueError as e:
        return api_error(str(e), 400)
    if not ok:
        return api_error("Watchlist not found", 404)
    return api_success()


@alerts_bp.route("/watchlists/<int:watchlist_id>", methods=["DELETE"])
def delete_watchlist(watchlist_id: int):
    if not watchlists.delete(watchlist_id):
        return api_error("Watchlist not found", 404)
    return api_success()


# ----------------------------------------------------------------------
# Push channels
# ----------------------------------------------------------------------


@alerts_bp.route("/channels", methods=["GET"])
def list_channels():
    return api_success(data={"channels": alert_channels.list_channels()})


@alerts_bp.route("/channels", methods=["POST"])
def create_channel():
    try:
        channel_id = alert_channels.create(request.get_json() or {})
    except ValueError as e:
        return api_error(str(e), 400)
    return api_success(data={"channel_id": channel_id})


@alerts_bp.route("/channels/<int:channel_id>", methods=["PUT", "PATCH"])
def update_channel(channel_id: int):
    try:
        ok = alert_channels.update(channel_id, request.get_json() or {})
    except ValueError as e:
        return api_error(str(e), 400)
    if not ok:
        return api_error("Channel not found", 404)
    return api_success()


@alerts_bp.route("/channels/<int:channel_id>", methods=["DELETE"])
def delete_channel(channel_id: int):
    if not alert_channels.delete(channel_id):
        return api_error("Channel not found", 404)
    return api_success()


@alerts_bp.route("/test", methods=["POST"])
@alerts_bp.route("/channels/<int:channel_id>/test", methods=["POST"])
def test_channels(channel_id: int | None = None):
    results = alert_channels.send_test(channel_id)
    if not results:
        return api_error("No enabled channel to test", 400)
    return api_success(data={"results": results})
