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
    clear_alerts,
    get_alert_count,
    get_alerts,
    get_statistics,
    init_db,
    update_alert_status,
)

from detector import (
    get_status,
    start_monitoring,
    stop_monitoring,
)


app = Flask(__name__)

app.config["JSON_SORT_KEYS"] = False

init_db()


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
# ALERT API
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
# START MONITORING
# =========================================================

@app.get("/start")
def start():

    success, message = start_monitoring()

    return redirect(
        url_for(
            "dashboard",
            started="1" if success else "0"
        )
    )


# =========================================================
# STOP MONITORING
# =========================================================

@app.get("/stop")
def stop():

    stop_monitoring()

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# CLEAR ALERTS
# =========================================================

@app.get("/clear")
def clear():

    clear_alerts()

    return redirect(
        url_for("dashboard")
    )


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
# NETWORK / MONITORING STATUS API
# =========================================================

@app.get("/status")
def status_api():

    return jsonify(
        get_status()
    )


# =========================================================
# 404 HANDLER
# =========================================================

@app.errorhandler(404)
def not_found(_error):

    return jsonify({
        "error": "Route not found."
    }), 404


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )