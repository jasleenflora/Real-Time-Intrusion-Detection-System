import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
import random
import threading
import sqlite3

# Database Setup
def setup_database():
    conn = sqlite3.connect("intrusion_logs.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        packet_size INTEGER, 
        alert TEXT
    )
    """)
    conn.commit()
    conn.close()

setup_database()

# Rule-Based Simulated Alerts Data
def generate_alert():
    packet_size = random.randint(50, 1500)
    protocol = random.choice(["TCP", "UDP", "ICMP"])
    source_ip = f"192.168.1.{random.randint(1, 255)}"
    destination_ip = f"192.168.1.{random.randint(1, 255)}"

    # Rule-Based Detection Logic
    if packet_size > 1400:
        alert_type = "DDoS Attack"
    elif protocol == "ICMP":
        alert_type = "MITM Attack"
    elif source_ip == destination_ip:
        alert_type = "Unauthorized Access"
    elif packet_size < 60:
        alert_type = "Malware"
    else:
        alert_type = random.choice(["Phishing", "Data Breach"])

    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "packet_size": packet_size,
        "alert_type": alert_type,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol
    }

# Main IDS GUI Class
class IntrusionDetectionSystem:
    def _init_(self, root):
        self.root = root
        self.root.title("Intrusion Detection System")
        self.root.geometry("1400x800")
        self.root.configure(bg="#1a1a2e")

        self.running = False
        self.alerts = []

        # Notebook (Tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both")

        # Tabs
        self.main_frame = ttk.Frame(self.notebook)
        self.database_frame = ttk.Frame(self.notebook)
        self.visualization_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.main_frame, text="Real-Time Monitoring")
        self.notebook.add(self.database_frame, text="Database Logs")
        self.notebook.add(self.visualization_frame, text="Visualization")

        self.setup_main_screen()
        self.setup_database_screen()
        self.setup_visualization_screen()

    # Real-Time Monitoring Screen
    def setup_main_screen(self):
        self.alert_display = tk.Listbox(self.main_frame, width=120, height=20, bg="#000", fg="#39ff14",
                                        font=("Courier", 14))
        self.alert_display.pack(pady=20)

        button_frame = tk.Frame(self.main_frame, bg="#1a1a2e")
        button_frame.pack(pady=20)

        start_button = tk.Button(button_frame, text="Start Monitoring", command=self.start_monitoring, bg="#27ae60",
                                 fg="white", font=("Arial", 16, "bold"), padx=30, pady=15)
        start_button.grid(row=0, column=0, padx=50)

        stop_button = tk.Button(button_frame, text="Stop Monitoring", command=self.stop_monitoring, bg="#c0392b",
                                fg="white", font=("Arial", 16, "bold"), padx=30, pady=15)
        stop_button.grid(row=0, column=1, padx=50)

    # Database Screen Setup
    def setup_database_screen(self):
        self.tree = ttk.Treeview(self.database_frame, columns=(
            "Timestamp", "Source IP", "Destination IP", "Protocol", "Packet Size", "Alert Type"), show='headings')
        for col in ("Timestamp", "Source IP", "Destination IP", "Protocol", "Packet Size", "Alert Type"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=140)
        self.tree.pack(expand=True, fill="both")

    # Visualization Screen Setup
    def setup_visualization_screen(self):
        graph_button = tk.Button(self.visualization_frame, text="Open Graphs", command=self.open_graph_window,
                                 bg="#2980b9", fg="white", font=("Arial", 16, "bold"), padx=30, pady=15)
        graph_button.pack(pady=20)

    def open_graph_window(self):
        graph_window = tk.Toplevel(self.root)
        graph_window.title("Alert Graphs")
        graph_window.geometry("800x600")

        fig, ax = plt.subplots(figsize=(8, 6))
        alert_counts = {}
        for alert in self.alerts:
            alert_counts[alert['alert_type']] = alert_counts.get(alert['alert_type'], 0) + 1

        ax.clear()
        ax.pie(alert_counts.values(), labels=alert_counts.keys(), autopct='%1.1f%%', startangle=90,
               colors=['red', 'blue', 'green', 'yellow', 'purple', 'orange'])
        ax.set_title("Alert Type Distribution")

        canvas = FigureCanvasTkAgg(fig, master=graph_window)
        canvas.get_tk_widget().pack(expand=True, fill='both')
        canvas.draw()

    # Start Monitoring Function
    def start_monitoring(self):
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self.monitor_network, daemon=True)
            self.monitor_thread.start()

    # Stop Monitoring Function
    def stop_monitoring(self):
        self.running = False

    # Network Monitoring Simulation
    def monitor_network(self):
        while self.running:
            alert = generate_alert()
            self.alerts.append(alert)
            self.alert_display.insert(tk.END,
                                      f"[{alert['timestamp']}] {alert['alert_type']} | Packet Size: {alert['packet_size']} bytes")
            self.tree.insert("", tk.END, values=(
                alert["timestamp"], alert["source_ip"], alert["destination_ip"], alert["protocol"],
                alert["packet_size"], alert["alert_type"]))
            self.save_to_database(alert)
            time.sleep(random.randint(2, 5))

    # Save to Database
    def save_to_database(self, alert):
        conn = sqlite3.connect("intrusion_logs.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO logs (timestamp, source_ip, destination_ip, protocol, packet_size, alert) VALUES (?, ?, ?, ?, ?, ?)",
            (alert["timestamp"], alert["source_ip"], alert["destination_ip"], alert["protocol"],
             alert["packet_size"], alert["alert_type"]))
        conn.commit()
        conn.close()

# Run GUI
if _name_ == "_main_":
    root = tk.Tk()
    app = IntrusionDetectionSystem(root)
    root.mainloop()