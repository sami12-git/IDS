import tkinter as tk
from scapy.all import sniff, IP, TCP
import threading
import datetime
import requests

packet_count = {}
alerted_ips = set()
port_scan = {}
blacklist = set()
running = False

THRESHOLD = 10
PORT_SCAN_LIMIT = 5

# 🌐 Get IP Location
def get_ip_location(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        return res.get("country", "Unknown")
    except:
        return "Unknown"

# GUI setup
root = tk.Tk()
root.title("🔥 Advanced IDS Pro Dashboard")
root.geometry("900x650")

text_area = tk.Text(root, height=30, width=110)
text_area.pack()

stats_label = tk.Label(root, text="Stats: ", font=("Arial", 12))
stats_label.pack()

def update_stats():
    total_packets = sum(packet_count.values())
    attackers = len(alerted_ips)
    stats_label.config(text=f"📊 Packets: {total_packets} | 🚨 Attackers: {attackers}")
    root.after(2000, update_stats)

def log_to_gui(message, color="black"):
    text_area.insert(tk.END, message + "\n", color)
    text_area.tag_config(color, foreground=color)
    text_area.see(tk.END)

def log_attack(ip, reason):
    location = get_ip_location(ip)
    timestamp = datetime.datetime.now()

    msg = f"{timestamp} - ALERT: {ip} ({location}) [{reason}]"
    log_to_gui(msg, "red")

    with open("alerts.txt", "a") as file:
        file.write(msg + "\n")

def packet_callback(packet):
    global running
    if not running:
        return

    if packet.haslayer(IP):
        src = packet[IP].src

        # 🚫 Block traffic (simulation)
        if src in blacklist:
            log_to_gui(f"🚫 BLOCKED: {src}", "red")
            return

        packet_count[src] = packet_count.get(src, 0) + 1
        log_to_gui(f"{src} → Count: {packet_count[src]}")

        # 🚨 DoS Detection
        if packet_count[src] > THRESHOLD and src not in alerted_ips:
            log_attack(src, "DoS Attack")
            alerted_ips.add(src)
            blacklist.add(src)

        # 🔍 Port Scan Detection
        if packet.haslayer(TCP):
            dport = packet[TCP].dport

            if src not in port_scan:
                port_scan[src] = set()

            port_scan[src].add(dport)

            if len(port_scan[src]) > PORT_SCAN_LIMIT and src not in alerted_ips:
                log_attack(src, "Port Scan")
                alerted_ips.add(src)
                blacklist.add(src)

def start_sniffing():
    global running
    running = True
    log_to_gui("🚀 IDS Started...", "blue")
    sniff(prn=packet_callback, store=0)

def stop_sniffing():
    global running
    running = False
    log_to_gui("⏹️ IDS Stopped", "blue")

def start_thread():
    thread = threading.Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()

def show_top_attacker():
    if packet_count:
        top = max(packet_count, key=packet_count.get)
        log_to_gui(f"🏆 Top Attacker: {top} ({packet_count[top]} packets)", "green")

def clear_screen():
    text_area.delete(1.0, tk.END)

# Buttons
frame = tk.Frame(root)
frame.pack(pady=10)

tk.Button(frame, text="Start IDS", command=start_thread, bg="green", fg="white").grid(row=0, column=0, padx=10)
tk.Button(frame, text="Stop IDS", command=stop_sniffing, bg="red", fg="white").grid(row=0, column=1, padx=10)
tk.Button(frame, text="Top Attacker", command=show_top_attacker, bg="blue", fg="white").grid(row=0, column=2, padx=10)
tk.Button(frame, text="Clear", command=clear_screen, bg="gray", fg="white").grid(row=0, column=3, padx=10)

update_stats()
root.mainloop()
