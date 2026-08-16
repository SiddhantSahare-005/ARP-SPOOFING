import os
import time
import threading
import requests

from scapy.all import sniff, ARP


# =========================================================
# CONFIGURATION
# =========================================================

API_URL = os.getenv(
    "ARPSHIELD_API_URL",
    "https://YOUR-APP.vercel.app/api/alerts"
)

CACHE_TIMEOUT = 300
ALERT_COOLDOWN = 30


# =========================================================
# DETECTOR STATE
# =========================================================

ip_mac_table = {}
last_alerts = {}

monitoring = False
monitor_thread = None

start_time = None
packets_seen = 0
alerts_detected = 0

state_lock = threading.Lock()


# =========================================================
# SEND ALERT TO VERCEL
# =========================================================

def send_alert(ip, old_mac, new_mac):

    global alerts_detected

    alert_key = f"{ip}:{old_mac}:{new_mac}"
    current_time = time.time()

    # Prevent duplicate alerts
    if alert_key in last_alerts:
        if current_time - last_alerts[alert_key] < ALERT_COOLDOWN:
            return

    last_alerts[alert_key] = current_time

    data = {
        "ip": ip,
        "mac": new_mac,
        "old_mac": old_mac,
        "alert_type": "ARP Spoofing",
        "severity": "HIGH",
        "message": (
            f"Possible ARP spoofing detected. "
            f"IP {ip} changed from {old_mac} to {new_mac}"
        ),
        "timestamp": time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }

    with state_lock:
        alerts_detected += 1

    try:
        response = requests.post(
            API_URL,
            json=data,
            timeout=10
        )

        if response.ok:
            print(
                f"[+] Alert sent to API: "
                f"{ip} -> {new_mac}"
            )
        else:
            print(
                f"[!] API returned HTTP "
                f"{response.status_code}"
            )

    except requests.exceptions.RequestException as e:
        print(f"[!] Could not send alert to API: {e}")


# =========================================================
# ARP PACKET ANALYSIS
# =========================================================

def detect_arp(packet):

    global packets_seen

    if not packet.haslayer(ARP):
        return

    with state_lock:
        packets_seen += 1

    arp = packet[ARP]

    # Only process ARP replies
    if arp.op != 2:
        return

    ip = arp.psrc
    mac = arp.hwsrc

    if not ip or not mac:
        return

    mac = mac.lower()

    # -----------------------------------------------------
    # First time seeing this IP
    # -----------------------------------------------------

    if ip not in ip_mac_table:

        ip_mac_table[ip] = {
            "mac": mac,
            "last_seen": time.time()
        }

        print(f"[+] Learned: {ip} -> {mac}")

        return

    # -----------------------------------------------------
    # Existing IP
    # -----------------------------------------------------

    old_mac = ip_mac_table[ip]["mac"]

    ip_mac_table[ip]["last_seen"] = time.time()

    # -----------------------------------------------------
    # MAC changed
    # -----------------------------------------------------

    if old_mac != mac:

        print("\n" + "=" * 60)
        print("[!!!] POSSIBLE ARP SPOOFING DETECTED")
        print(f"IP Address : {ip}")
        print(f"Old MAC    : {old_mac}")
        print(f"New MAC    : {mac}")
        print("=" * 60 + "\n")

        send_alert(
            ip=ip,
            old_mac=old_mac,
            new_mac=mac
        )

        # Update mapping
        ip_mac_table[ip]["mac"] = mac


# =========================================================
# CLEAN OLD ENTRIES
# =========================================================

def cleanup_table():

    current_time = time.time()

    expired = []

    for ip, data in list(ip_mac_table.items()):

        if current_time - data["last_seen"] > CACHE_TIMEOUT:
            expired.append(ip)

    for ip in expired:

        del ip_mac_table[ip]

        print(
            f"[*] Removed expired mapping: {ip}"
        )


# =========================================================
# MONITORING LOOP
# =========================================================

def monitoring_loop():

    global monitoring

    print("=" * 60)
    print("       ARP SHIELD - ARP SPOOF DETECTOR")
    print("=" * 60)

    print(f"[*] API: {API_URL}")
    print("[*] ARP monitoring started")
    print()

    while monitoring:

        try:

            sniff(
                filter="arp",
                prn=detect_arp,
                store=False,
                timeout=10
            )

            cleanup_table()

        except Exception as e:

            print(
                f"[!] Monitoring error: {e}"
            )

            time.sleep(2)

    print("[*] ARP monitoring stopped.")


# =========================================================
# START MONITORING
# =========================================================

def start_monitoring():

    global monitoring
    global monitor_thread
    global start_time
    global packets_seen
    global alerts_detected

    if monitoring:

        return False, "Monitoring is already running."

    monitoring = True

    start_time = time.time()

    packets_seen = 0
    alerts_detected = 0

    monitor_thread = threading.Thread(
        target=monitoring_loop,
        daemon=True
    )

    monitor_thread.start()

    return True, "ARP monitoring started successfully."


# =========================================================
# STOP MONITORING
# =========================================================

def stop_monitoring():

    global monitoring

    monitoring = False

    return True


# =========================================================
# GET MONITORING STATUS
# =========================================================

def get_status():

    with state_lock:

        packet_count = packets_seen
        alert_count = alerts_detected

    if monitoring:

        uptime = (
            int(time.time() - start_time)
            if start_time
            else 0
        )

    else:

        uptime = 0

    return {
        "running": monitoring,
        "status": "Running" if monitoring else "Stopped",
        "packets_seen": packet_count,
        "alerts_detected": alert_count,
        "uptime_seconds": uptime,
        "api_url": API_URL
    }


# =========================================================
# STANDALONE MODE
# =========================================================

def main():

    success, message = start_monitoring()

    print(message)

    if not success:
        return

    try:

        while monitoring:
            time.sleep(1)

    except KeyboardInterrupt:

        print("\n[*] Stopping ARP Shield...")

        stop_monitoring()


# =========================================================
# RUN DIRECTLY
# =========================================================

if __name__ == "__main__":
    main()