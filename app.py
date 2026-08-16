from math import ceil

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from db import (
    add_alert,
    clear_alerts,
    get_alert_count,
    get_alerts,
    get_statistics,
    init_db,
    update_alert_status,
)


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)

app.config["JSON_SORT_KEYS"] = False

init_db()


# =========================================================
# CLOUD STATUS
# =========================================================

def get_status():
    return {
        "running": True,
        "status": "Cloud API Online",
        "packets_seen": 0,
        "alerts_detected": get_alert_count(),
        "uptime_seconds": 0,
        "mode": "Cloud Dashboard"
    }


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/")
def dashboard():

    page = request.args.get(
        "page",
        1,
        type=int
    )

    started = request.args.get(
        "started",
        "0"
    )

    per_page = 50

    total = get_alert_count()

    total_pages = max(
        1,
        ceil(total / per_page)
    )

    page = min(
        max(1, page),
        total_pages
    )

    return render_template(
        "dashboard.html",

        alerts=get_alerts(
            page,
            per_page
        ),

        stats=get_statistics(),

        page=page,

        total_pages=total_pages,

        status=get_status(),

        started=started
    )


# =========================================================
# GET ALERTS API
# =========================================================

@app.get("/alerts")
def alerts_api():

    page = request.args.get(
        "page",
        1,
        type=int
    )

    per_page = min(
        max(
            request.args.get(
                "per_page",
                50,
                type=int
            ),
            1
        ),
        100
    )

    total = get_alert_count()

    total_pages = max(
        1,
        ceil(total / per_page)
    )

    page = min(
        max(1, page),
        total_pages
    )

    return jsonify({
        "alerts": get_alerts(
            page,
            per_page
        ),

        "stats": get_statistics(),

        "page": page,

        "total_pages": total_pages,

        "status": get_status(),
    })


# =========================================================
# RECEIVE ALERT FROM LOCAL ARP DETECTOR
# =========================================================

@app.post("/api/alerts")
def receive_alert():

    data = request.get_json(
        silent=True
    ) or {}

    required_fields = [
        "ip",
        "mac",
        "old_mac",
        "alert_type",
        "severity",
        "message",
        "timestamp",
    ]

    missing = [
        field
        for field in required_fields
        if not data.get(field)
    ]

    if missing:

        return jsonify({
            "success": False,
            "error": "Missing required fields",
            "fields": missing
        }), 400

    try:

        add_alert(
            timestamp=data["timestamp"],
            source_ip=data["ip"],
            source_mac=data["mac"],
            previous_mac=data["old_mac"],
            attack_type=data["alert_type"],
            severity=data["severity"],
            description=data["message"],
            status="Open"
        )

        return jsonify({
            "success": True,
            "message": "Alert stored successfully"
        }), 201

    except Exception as e:

        print(
            f"[!] Failed to store alert: {e}"
        )

        return jsonify({
            "success": False,
            "error": "Failed to store alert"
        }), 500


# =========================================================
# START ROUTE
# =========================================================

@app.get("/start")
def start():

    return redirect(
        url_for(
            "dashboard",
            started="1"
        )
    )


# =========================================================
# STOP ROUTE
# =========================================================

@app.get("/stop")
def stop():

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# CLEAR ALL ALERTS
# =========================================================

@app.get("/clear")
def clear():

    try:

        clear_alerts()

        return redirect(
            url_for("dashboard")
        )

    except Exception as e:

        print(
            f"[!] Clear alerts failed: {e}"
        )

        return jsonify({
            "success": False,
            "error": "Failed to clear alerts"
        }), 500


# =========================================================
# UPDATE ALERT STATUS
# =========================================================

@app.post("/alerts/<int:alert_id>/status")
def set_status(alert_id):

    data = request.get_json(
        silent=True
    ) or {}

    status = data.get(
        "status",
        "Open"
    )

    if not update_alert_status(
        alert_id,
        status
    ):

        return jsonify({
            "error":
            "Invalid status or alert not found."
        }), 400

    return jsonify({
        "success": True
    })


# =========================================================
# STATUS API
# =========================================================

@app.get("/status")
def status_api():

    return jsonify(
        get_status()
    )


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "ARP Shield",
        "database": "Supabase"
    })


# =========================================================
# 404 HANDLER
# =========================================================

@app.errorhandler(404)
def not_found(_error):

    return jsonify({
        "error": "Route not found."
    }), 404


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
