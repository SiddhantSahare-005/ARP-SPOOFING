import os
import requests


# =========================================================
# SUPABASE CONFIGURATION
# =========================================================

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SECRET_KEY")


if not SUPABASE_URL:
    raise RuntimeError(
        "SUPABASE_URL is not configured."
    )

if not SUPABASE_KEY:
    raise RuntimeError(
        "SUPABASE_SECRET_KEY is not configured."
    )


TABLE_URL = f"{SUPABASE_URL}/rest/v1/alerts"


# =========================================================
# SUPABASE HEADERS
# =========================================================

def get_headers():

    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
    }


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def init_db():

    # The alerts table is created in Supabase
    # using the SQL Editor.
    pass


# =========================================================
# ADD ALERT
# =========================================================

def add_alert(
    timestamp,
    source_ip,
    source_mac,
    previous_mac,
    attack_type,
    severity,
    description,
    status="Open",
):

    data = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_mac": source_mac,
        "previous_mac": previous_mac,
        "attack_type": attack_type,
        "severity": severity,
        "description": description,
        "status": status,
    }

    response = requests.post(
        TABLE_URL,
        headers={
            **get_headers(),
            "Prefer": "return=minimal",
        },
        json=data,
        timeout=10,
    )

    response.raise_for_status()


# =========================================================
# GET ALERTS
# =========================================================

def get_alerts(page=1, per_page=50):

    page = max(1, int(page))
    per_page = max(
        1,
        min(100, int(per_page))
    )

    offset = (page - 1) * per_page

    params = {
        "select": "*",
        "order": "id.desc",
        "limit": per_page,
        "offset": offset,
    }

    response = requests.get(
        TABLE_URL,
        headers=get_headers(),
        params=params,
        timeout=10,
    )

    response.raise_for_status()

    return response.json()


# =========================================================
# GET ALERT COUNT
# =========================================================

def get_alert_count():

    response = requests.get(
        TABLE_URL,
        headers={
            **get_headers(),
            "Prefer": "count=exact",
        },
        params={
            "select": "id",
        },
        timeout=10,
    )

    response.raise_for_status()

    content_range = response.headers.get(
        "Content-Range",
        "",
    )

    if "/" in content_range:

        total = content_range.split("/")[-1]

        if total != "*":
            return int(total)

    return len(response.json())


# =========================================================
# GET STATISTICS
# =========================================================

def get_statistics():

    response = requests.get(
        TABLE_URL,
        headers=get_headers(),
        params={
            "select": "severity",
        },
        timeout=10,
    )

    response.raise_for_status()

    rows = response.json()

    total = len(rows)

    high = sum(
        1
        for row in rows
        if row.get("severity") == "HIGH"
    )

    medium = sum(
        1
        for row in rows
        if row.get("severity") == "MEDIUM"
    )

    low = sum(
        1
        for row in rows
        if row.get("severity") == "LOW"
    )

    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
    }


# =========================================================
# CLEAR ALL ALERTS
# =========================================================

def clear_alerts():

    response = requests.delete(
        TABLE_URL,
        headers={
            **get_headers(),
            "Prefer": "return=minimal",
        },
        params={
            "id": "gt.0",
        },
        timeout=10,
    )

    if not response.ok:

        print(
            f"[!] Clear alerts failed: "
            f"HTTP {response.status_code}"
        )

        print(response.text)

    response.raise_for_status()

    print("[+] All alerts cleared successfully.")


# =========================================================
# UPDATE ALERT STATUS
# =========================================================

def update_alert_status(
    alert_id,
    status,
):

    if status not in {
        "Open",
        "Investigating",
        "Resolved",
    }:
        return False

    response = requests.patch(
        TABLE_URL,
        headers={
            **get_headers(),
            "Prefer": "return=minimal",
        },
        params={
            "id": f"eq.{alert_id}",
        },
        json={
            "status": status,
        },
        timeout=10,
    )

    response.raise_for_status()

    return True
