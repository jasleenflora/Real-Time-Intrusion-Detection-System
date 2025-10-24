Real-Time Intrusion Detection System (IDS)

1.Project Overview:

The Real-Time Intrusion Detection System (IDS) is a Python-based desktop application that simulates and visualizes network intrusion activities in real time.
It detects and categorizes various simulated cyberattacks using rule-based logic, logs all suspicious activities into an SQLite database, and provides graphical visualization for better insight into network behavior.

2.Tech Stack:-

Language: Python

GUI Framework: Tkinter

Visualization: Matplotlib

Database: SQLite3

Threading: Multithreading for real-time data simulation

3.Features:-

Real-Time Monitoring:
Simulates and displays incoming network packets with potential alerts in real time.

Rule-Based Detection Engine:
Detects attack types like:

DDoS Attack

MITM (Man-in-the-Middle)

Unauthorized Access

Malware

Phishing / Data Breach

Database Logging:
Stores every alert with timestamp, source IP, destination IP, protocol, and packet size in an SQLite database (intrusion_logs.db).

Graphical Visualization:
Generates pie charts representing attack distribution using Matplotlib.

Multi-Tabbed Interface:

Real-Time Monitoring Tab → Displays live alerts

Database Logs Tab → Shows stored intrusion records

Visualization Tab → Opens graphs dynamically

4.GUI Overview:-

Built using Tkinter’s ttk.Notebook for tabbed UI.

Custom color scheme for dark, modern look.

Buttons for Start Monitoring, Stop Monitoring, and View Graphs.

5.Working Logic:-

The system continuously simulates network packets (random IPs, protocols, and packet sizes).

Rule-based conditions classify each packet into a specific intrusion type.

Each detected alert is:

Displayed live on the dashboard

Stored in the SQLite database

Counted for visualization metrics

Database Schema (intrusion_logs.db):-

Column	Type	Description

id	INTEGER	Primary Key

timestamp	TEXT	Time of detection

source_ip	TEXT	Source IP address

destination_ip	TEXT	Destination IP address

protocol	TEXT	Protocol type (TCP/UDP/ICMP)

packet_size	INTEGER	Size of packet (bytes)

alert	TEXT	Type of detected intrusion

6.How to Run:-

Install dependencies:

pip install matplotlib

Run the script:

python intrusion_detection_system.py

The GUI will launch.

Click Start Monitoring to begin.

Switch to Database Logs to view stored data.

Open Visualization to see attack distribution charts.

7.Future Enhancements:-

Integrate real network packet sniffing using Scapy.

Add email or SMS alerts for high-risk detections.

Use Machine Learning models for intelligent anomaly detection.

Create web-based dashboard for remote monitoring.
