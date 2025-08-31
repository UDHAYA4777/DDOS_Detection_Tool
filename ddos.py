#!/usr/bin/env python3
"""
Easy DDoS Traffic Monitor
- Captures packets and checks for DDoS-like patterns
- Alerts via console + popup (if GUI available)
- Saves charts automatically (no blocking)
"""

import os
import sys
import time
import threading
from collections import Counter
from datetime import datetime

import requests
from scapy.all import sniff, IP

# Try GUI (Tkinter). If not available, fall back to console only
try:
    import tkinter as tk
    from tkinter import messagebox
    TK_AVAILABLE = True
except:
    TK_AVAILABLE = False

# Matplotlib (for charts)
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


# ---------------- Config ----------------
MONITOR_DURATION = 15        # seconds per cycle
PACKET_THRESHOLD = 100       # minimum packets
UNIQUE_IP_THRESHOLD = 50     # minimum unique IPs
TOP_N_DISPLAY = 10           # how many IPs to plot

# Output files
LOG_FILE = "alerts.log"
OUTPUT_DIR = "."
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---------------- State ----------------
ip_counter = Counter()
ip_cache = {}
last_alert_time = 0
ALERT_COOLDOWN = 60  # seconds


# ---------------- Helpers ----------------
def get_ip_location(ip):
    """Fetch IP country using ipinfo.io (cached)."""
    if ip in ip_cache:
        return ip_cache[ip]
    try:
        url = f"http://ipinfo.io/{ip}/json"
        r = requests.get(url, timeout=3)
        if r.status_code == 200:
            country = r.json().get("country", "Unknown") or "Unknown"
        else:
            country = "Unknown"
    except:
        country = "Unknown"
    ip_cache[ip] = country
    return country


def show_popup(message):
    """Show alert popup in background (if GUI available)."""
    if not TK_AVAILABLE:
        print("[!] ALERT:", message)
        return

    def _popup():
        root = tk.Tk()
        root.withdraw()
        messagebox.showwarning("DDoS Attack Alert", message)
        root.destroy()

    threading.Thread(target=_popup, daemon=True).start()


def save_chart(counter):
    """Save bar chart of top IPs."""
    if not counter:
        return
    ips, counts = zip(*counter.most_common(TOP_N_DISPLAY))
    plt.figure(figsize=(8, 4))
    plt.bar(ips, counts)
    plt.xlabel("IP Addresses")
    plt.ylabel("Packet Count")
    plt.title("Top IPs in Traffic")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(OUTPUT_DIR, f"traffic_{ts}.png")
    plt.savefig(path)
    plt.close()
    print(f"[+] Chart saved: {path}")


def log_alert(message):
    """Append alert to log file."""
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {message}\n")


# ---------------- Packet Processing ----------------
def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ip_counter[src_ip] += 1


# ---------------- Main Monitor ----------------
def monitor_traffic():
    global last_alert_time

    print("[+] Starting DDoS traffic monitor...")
    print(f"[+] Monitoring every {MONITOR_DURATION}s (threshold={PACKET_THRESHOLD} packets & {UNIQUE_IP_THRESHOLD} unique IPs)")
    print(f"[+] Logs saved in: {LOG_FILE}\n")

    try:
        while True:
            ip_counter.clear()

            sniff(prn=process_packet, store=0, timeout=MONITOR_DURATION, filter="ip")

            total_packets = sum(ip_counter.values())
            unique_ips = len(ip_counter)

            print(f"\n[+] Window summary: {total_packets} packets, {unique_ips} unique IPs")

            suspicious = (total_packets > PACKET_THRESHOLD and unique_ips > UNIQUE_IP_THRESHOLD)
            now = time.time()

            if suspicious and now - last_alert_time > ALERT_COOLDOWN:
                last_alert_time = now

                # Build alert message
                top_ips = []
                for ip, count in ip_counter.most_common(5):
                    country = get_ip_location(ip)
                    top_ips.append(f"{ip} ({country}): {count}")
                alert_msg = "Possible DDoS detected!\n\nTop IPs:\n" + "\n".join(top_ips)

                # Console + log + popup + chart
                print("[!] ALERT:", alert_msg)
                log_alert(alert_msg)
                show_popup(alert_msg)
                save_chart(ip_counter)
            else:
                print("[+] No DDoS pattern detected.")

    except KeyboardInterrupt:
        print("\n[+] Stopping monitor. Bye!")


if __name__ == "__main__":
    monitor_traffic()
