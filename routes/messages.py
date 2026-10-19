"""Decoded-message database API: search, export, retention settings."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from flask import Blueprint, Response, render_template, request

from utils import message_store
from utils.responses import api_error, api_success

messages_bp = Blueprint("messages", __name__, url_prefix="/messages")

_EXPORT_COLUMNS = ["id", "time", "mode", "event_type", "ident", "aliases", "freq_hz", "lat", "lon", "summary", "text"]


def _time_arg(name: str) -> float | None:
    value = request.args.get(name)
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        raise ValueError(f"{name} must be epoch seconds or an ISO time") from None


def _filters() -> dict:
    modes = [m.strip() for m in (request.args.get("mode") or "").split(",") if m.strip()]
    return {
        "q": request.args.get("q", ""),
        "modes": modes,
        "ident": (request.args.get("ident") or "").strip() or None,
        "since": _time_arg("since"),
        "until": _time_arg("until"),
        "has_position": request.args.get("has_position") in ("1", "true", "yes"),
        "before_id": request.args.get("before_id", type=int),
    }


@messages_bp.route("", methods=["GET"])
def page():
    """The Messages page: search and export everything the decoders heard."""
    return render_template("messages.html")


@messages_bp.route("/search", methods=["GET"])
def search():
    try:
        filters = _filters()
    except ValueError as e:
        return api_error(str(e), 400)
    limit = request.args.get("limit", default=100, type=int)
    return api_success(data=message_store.search(filters, limit=limit))


@messages_bp.route("/<int:message_id>", methods=["GET"])
def get_message(message_id: int):
    message = message_store.get(message_id)
    if not message:
        return api_error("Message not found", 404)
    return api_success(data={"message": message})


@messages_bp.route("/export", methods=["GET"])
def export():
    try:
        filters = _filters()
    except ValueError as e:
        return api_error(str(e), 400)
    filters.pop("before_id", None)
    fmt = request.args.get("format", "csv")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":

        def generate_json():
            yield "["
            for i, row in enumerate(message_store.iter_matching(filters)):
                yield ("," if i else "") + "\n" + json.dumps(row, default=str)
            yield "\n]\n"

        return Response(
            generate_json(),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=intercept_messages_{stamp}.json"},
        )

    if fmt != "csv":
        return api_error("format must be csv or json", 400)

    def generate_csv():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(_EXPORT_COLUMNS)
        for row in message_store.iter_matching(filters):
            writer.writerow(
                [
                    row["id"],
                    datetime.fromtimestamp(row["ts"]).isoformat(timespec="seconds"),
                    row["mode"],
                    row["event_type"],
                    row["ident"],
                    " ".join(row["aliases"]),
                    row["freq_hz"],
                    row["lat"],
                    row["lon"],
                    row["summary"],
                    row["text"],
                ]
            )
            if buf.tell() > 64_000:
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate()
        yield buf.getvalue()

    return Response(
        generate_csv(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=intercept_messages_{stamp}.csv"},
    )


@messages_bp.route("/stats", methods=["GET"])
def stats():
    return api_success(data=message_store.stats())


@messages_bp.route("/settings", methods=["PUT", "PATCH"])
def update_settings():
    try:
        settings = message_store.update_settings(request.get_json() or {})
    except (TypeError, ValueError) as e:
        return api_error(str(e), 400)
    message_store.apply_retention()
    return api_success(data={"settings": settings})


@messages_bp.route("", methods=["DELETE"])
def clear():
    return api_success(data={"deleted": message_store.clear()})
