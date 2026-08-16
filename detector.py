import ipaddress
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

from scapy.all import ARP, conf, get_if_addr, sniff

from db import add_alert


BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "arp_events.log"

LOG_DIR.mkdir(exist_ok=True)

logger = logging.getLogger("arp_shield")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.FileHandler(
        LOG_FILE,
        encoding="utf-8"
    )

    handler.setFormatter(
        logging.Formatter("%(message)s")
    )

    logger.addHandler(handler)


class ARPDetector:

    def __init__(self):

        self.ip_to_mac = {}
        self.mac_to_ips = defaultdict(set)
        self.response_times = defaultdict(deque)
        self.alert_cache = {}

        self.lock = threading.Lock()
        self.stop_event = threading.Event()

        self.sniffer_thread = None

        self.running = False
        self.last_error = None

        self.interface = None
        self.local_ip = None
        self.netmask = None
        self.network = None

        self.rapid_window_seconds = 10
        self.rapid_response_threshold = 20
        self.alert_cooldown_seconds = 15

    # =====================================================
    # FIND ACTIVE NETWORK INTERFACE
    # =====================================================

    def detect_network(self):

        try:

            # Get Scapy's routing information
            route = conf.route.route("0.0.0.0")

            if not route:
                raise RuntimeError(
                    "Could not determine the active network interface."
                )

            interface = route[0]

            # Get local IP assigned to that interface
            local_ip = get_if_addr(interface)

            if not local_ip or local_ip == "0.0.0.0":

                raise RuntimeError(
                    "Could not determine the local IP address."
                )

            # Avoid loopback
            if local_ip.startswith("127."):

                raise RuntimeError(
                    "Scapy selected the loopback interface. "
                    "Please check your active network adapter."
                )

            # Try to get interface information
            netmask = None

            try:

                iface_obj = conf.ifaces.dev_from_name(
                    str(interface)
                )

                if iface_obj:

                    netmask = getattr(
                        iface_obj,
                        "netmask",
                        None
                    )

            except Exception:
                pass

            # Windows/Scapy fallback
            if not netmask:

                netmask = "255.255.255.0"

            network = ipaddress.IPv4Network(
                f"{local_ip}/{netmask}",
                strict=False
            )

            self.interface = interface
            self.local_ip = local_ip
            self.netmask = netmask
            self.network = str(network)

            return True

        except Exception as exc:

            self.last_error = str(exc)

            return False

    # =====================================================
    # TIME
    # =====================================================

    def _now(self):

        return datetime.now().astimezone().isoformat(
            timespec="seconds"
        )

    # =====================================================
    # LOG ALERT
    # =====================================================

    def _log_event(
        self,
        source_ip,
        source_mac,
        previous_mac,
        attack_type,
        severity,
        description
    ):

        timestamp = self._now()

        add_alert(
            timestamp,
            source_ip,
            source_mac,
            previous_mac,
            attack_type,
            severity,
            description
        )

        logger.info(
            "[%s]\n"
            "%s\n"
            "IP: %s\n"
            "Source MAC: %s\n"
            "Previous MAC: %s\n"
            "Severity: %s\n"
            "Description: %s\n",
            timestamp,
            attack_type.upper(),
            source_ip or "N/A",
            source_mac or "N/A",
            previous_mac or "N/A",
            severity,
            description
        )

    # =====================================================
    # ALERT COOLDOWN
    # =====================================================

    def _should_alert(self, key):

        now = time.monotonic()

        last = self.alert_cache.get(key)

        if (
            last is not None
            and now - last < self.alert_cooldown_seconds
        ):
            return False

        self.alert_cache[key] = now

        return True

    # =====================================================
    # PROCESS ARP PACKETS
    # =====================================================

    def process_packet(self, packet):

        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]

        source_ip = arp.psrc
        source_mac = arp.hwsrc
        target_ip = arp.pdst

        if not source_ip or not source_mac:
            return

        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            return

        with self.lock:

            previous_mac = self.ip_to_mac.get(
                source_ip
            )

            # ---------------------------------------------
            # IP -> MAC CHANGE
            # ---------------------------------------------

            if (
                previous_mac
                and previous_mac.lower()
                != source_mac.lower()
            ):

                key = (
                    "mapping-change",
                    source_ip,
                    source_mac.lower()
                )

                if self._should_alert(key):

                    self._log_event(
                        source_ip,
                        source_mac,
                        previous_mac,
                        "ARP Spoofing",
                        "HIGH",
                        (
                            f"IP {source_ip} changed "
                            f"from MAC {previous_mac} "
                            f"to {source_mac}."
                        )
                    )

            # ---------------------------------------------
            # SAME IP -> MULTIPLE MAC
            # ---------------------------------------------

            known_macs = set()

            if previous_mac:
                known_macs.add(
                    previous_mac.lower()
                )

            known_macs.add(
                source_mac.lower()
            )

            if len(known_macs) > 1:

                key = (
                    "multiple-macs",
                    source_ip
                )

                if self._should_alert(key):

                    self._log_event(
                        source_ip,
                        source_mac,
                        previous_mac,
                        "Multiple MACs for IP",
                        "HIGH",
                        (
                            f"IP {source_ip} is associated "
                            f"with multiple MAC addresses."
                        )
                    )

            # ---------------------------------------------
            # SAME MAC -> MULTIPLE IP
            # ---------------------------------------------

            mac_key = source_mac.lower()

            previous_ips = self.mac_to_ips[
                mac_key
            ]

            if (
                source_ip not in previous_ips
                and previous_ips
            ):

                key = (
                    "multiple-ips",
                    mac_key
                )

                if self._should_alert(key):

                    ips = ", ".join(
                        sorted(previous_ips)
                    )

                    self._log_event(
                        source_ip,
                        source_mac,
                        previous_mac,
                        "Multiple IPs for MAC",
                        "MEDIUM",
                        (
                            f"MAC {source_mac} is associated "
                            f"with multiple IP addresses "
                            f"({ips}, {source_ip})."
                        )
                    )

            # ---------------------------------------------
            # GRATUITOUS ARP
            # ---------------------------------------------

            if (
                arp.op == 2
                and source_ip == target_ip
            ):

                key = (
                    "gratuitous",
                    source_ip,
                    source_mac.lower()
                )

                if self._should_alert(key):

                    self._log_event(
                        source_ip,
                        source_mac,
                        previous_mac,
                        "Gratuitous ARP",
                        "MEDIUM",
                        (
                            f"Gratuitous ARP reply observed "
                            f"for {source_ip}."
                        )
                    )

            # ---------------------------------------------
            # RAPID ARP RESPONSES
            # ---------------------------------------------

            if arp.op == 2:

                now = time.monotonic()

                times = self.response_times[
                    mac_key
                ]

                times.append(now)

                while (
                    times
                    and now - times[0]
                    > self.rapid_window_seconds
                ):

                    times.popleft()

                if (
                    len(times)
                    >= self.rapid_response_threshold
                ):

                    key = (
                        "rapid",
                        mac_key
                    )

                    if self._should_alert(key):

                        self._log_event(
                            source_ip,
                            source_mac,
                            previous_mac,
                            "Abnormal ARP Rate",
                            "HIGH",
                            (
                                f"{len(times)} ARP replies "
                                f"observed from {source_mac} "
                                f"within "
                                f"{self.rapid_window_seconds} "
                                f"seconds."
                            )
                        )

            # ---------------------------------------------
            # UPDATE MAPPING
            # ---------------------------------------------

            self.ip_to_mac[source_ip] = source_mac

            self.mac_to_ips[
                mac_key
            ].add(source_ip)

    # =====================================================
    # START MONITORING
    # =====================================================

    def start(self):

        with self.lock:

            if self.running:

                return (
                    False,
                    "Monitoring is already running."
                )

            self.stop_event.clear()
            self.last_error = None

            if not self.detect_network():

                self.running = False

                return (
                    False,
                    self.last_error
                    or
                    "Unable to detect active network."
                )

            self.running = True

        self.sniffer_thread = threading.Thread(
            target=self._sniff_worker,
            daemon=True,
            name="arp-sniffer"
        )

        self.sniffer_thread.start()

        return (
            True,
            (
                f"Monitoring started on "
                f"{self.local_ip} "
                f"({self.network})"
            )
        )

    # =====================================================
    # SCAPY SNIFFER
    # =====================================================

    def _sniff_worker(self):

        try:

            print(
                f"[ARP Shield] Monitoring interface: "
                f"{self.interface}"
            )

            print(
                f"[ARP Shield] Local IP: "
                f"{self.local_ip}"
            )

            print(
                f"[ARP Shield] Network: "
                f"{self.network}"
            )

            print(
                "[ARP Shield] Waiting for ARP packets..."
            )

            # IMPORTANT:
            # Do NOT use filter="arp".
            #
            # Some Windows/Npcap interfaces reject
            # the BPF filter. Instead, capture packets
            # and filter ARP packets in Python.

            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=False,
                lfilter=lambda packet:
                    packet.haslayer(ARP),
                stop_filter=lambda packet:
                    self.stop_event.is_set()
            )

        except PermissionError:

            self.last_error = (
                "Permission denied. "
                "Run PowerShell as Administrator."
            )

        except Exception as exc:

            self.last_error = str(exc)

            print(
                f"[ARP Shield] Capture error: {exc}"
            )

        finally:

            self.running = False

    # =====================================================
    # STOP
    # =====================================================

    def stop(self):

        if not self.running:

            return (
                False,
                "Monitoring is already stopped."
            )

        self.stop_event.set()

        self.running = False

        return (
            True,
            "ARP monitoring stopped."
        )

    # =====================================================
    # STATUS
    # =====================================================

    def status(self):

        return {

            "running": bool(
                self.running
            ),

            "error": self.last_error,

            "learned_mappings": len(
                self.ip_to_mac
            ),

            "interface": str(
                self.interface
            ) if self.interface else None,

            "local_ip": self.local_ip,

            "netmask": self.netmask,

            "network": self.network,
        }


_detector = ARPDetector()


def get_detector():
    return _detector


def start_monitoring():
    return _detector.start()


def stop_monitoring():
    return _detector.stop()


def get_status():
    return _detector.status()