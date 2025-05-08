from scapy.all import sniff
from collections import Counter
import time
import requests
import tkinter as tk
from tkinter import messagebox
import matplotlib.pyplot as plt


def get_ip_location(ip):
    try:
        url = f"http://ipinfo.io/{ip}/json"
        response = requests.get(url)
        data = response.json()
        return data.get('country', 'Unknown')
    except Exception as e:
        return 'Unknown'
def show_popup(message):
    root = tk.Tk()
    root.withdraw()  
    messagebox.showwarning("DDoS Attack Alert", message)
    root.destroy()
ip_counter = Counter()


PACKET_THRESHOLD = 100
UNIQUE_IP_THRESHOLD = 50
MONITOR_DURATION = 15 

# Traffic analysis function
def process_packet(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        ip_counter[src_ip] += 1

def monitor_traffic():
    print("[+] Starting continuous packet capture...")

    
    while True:
        
        sniff(prn=process_packet, store=0, timeout=MONITOR_DURATION)

        total_packets = sum(ip_counter.values())
        print(f"\n[+] Total packets captured: {total_packets}")
        print(f"[+] Unique IPs: {len(ip_counter)}")

        if total_packets > PACKET_THRESHOLD and len(ip_counter) > UNIQUE_IP_THRESHOLD:
            print("[!] Potential DDoS attack detected!")
            print("[!] Top IPs with geolocation:")

            alert_message = "Potential DDoS attack detected!\n\nTop IPs:\n"
            for ip, count in ip_counter.most_common(5):
                location = get_ip_location(ip)
                print(f"{ip} ({location}): {count} packets")
                alert_message += f"{ip} ({location}): {count} packets\n"

            show_popup(alert_message)

            ips, counts = zip(*ip_counter.most_common(10))
            plt.bar(ips, counts)
            plt.xlabel("IP Addresses")
            plt.ylabel("Packet Count")
            plt.title("Top 10 IPs in Traffic")
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.show()

        else:
            print("[+] No DDoS pattern detected.")

if __name__ == "__main__":
    monitor_traffic()
