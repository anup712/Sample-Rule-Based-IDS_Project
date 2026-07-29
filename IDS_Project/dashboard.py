# IDS DASHBOARD MODULE

# This file keeps track of:
# 1. Total packets captured.
# 2. Suspicious packets detected.
# 3. Number of unique source IP addresses.
# 4. Live network activity graph.
# 5. Alerts over time.
# 6. Packets per port.
# 7. Top source IP addresses.
# 8. Recent alerts.
# 9. Updating the GUI dashboard.

# Import Required Libraries

# Used to get the current date and time.
from datetime import datetime

# Used to count packets and IP addresses.
from collections import Counter

# Import the functions that update
# the IDS dashboard and live graph.
from gui import update_gui, update_graph

# Dashboard Statistics
# Stores the total number of packets captured.
total_packets = 0

# Stores the total number of suspicious packets detected.
suspicious_packets = 0

# Stores the total number of blocked IP addresses.
# (Will be updated later.)
blocked_ips = 0

# Stores only unique source IP addresses.
unique_ips = set()

# Live Network Activity Graph

# Stores the capture time of each packet.
packet_times = []

# Stores the total packet count.
packet_counts = []

# Alerts Over Time

# Stores the time when an alert occurred.
alert_times = []

# Stores the total alert count.
alert_counts = []

# Packets Per Port

# Counts how many packets arrive on each port.
port_counter = Counter()

# Top Source IP Addresses

# Counts how many packets are received
# from each source IP address.
ip_counter = Counter()

# Recent Alerts

# Stores the latest alert information.
# Each alert will contain:
# Time
# Source IP
# Attack Name
# Port
recent_alerts = []



# Function: update_dashboard()
# Purpose:
#     Updates IDS statistics whenever
#     a new packet is captured.

def update_dashboard(src_ip, is_suspicious):

    # Tell Python that we want to modify
    # the global variables declared above.
    global total_packets
    global suspicious_packets

    # Increase the packet counter.
    total_packets += 1

    # Save the source IP.
    unique_ips.add(src_ip)

    # Count packets from each source IP.
    ip_counter[src_ip] += 1

    # Check whether the packet is suspicious.
    if is_suspicious:

        # Increase the suspicious alert counter.
        suspicious_packets += 1

        # Save the alert time.
        alert_times.append(
	     datetime.now().strftime("%H:%M:%S")
	     )
        # Save the current alert count.
        alert_counts.append(suspicious_packets)

    # Update Dashboard Labels

    update_gui(
        total_packets,
        suspicious_packets,
        len(unique_ips)
    )

    # Save Data for Live Network Activity Graph

    packet_times.append(
        datetime.now().strftime("%H:%M:%S")
    )
    packet_counts.append(
        total_packets
    )

    # Update Live Graph
    # Display only the latest packet values.
    MAX_POINTS = 50
    x_data = list(range(max(0,len(packet_counts) - MAX_POINTS),len(packet_counts)))
    y_data = packet_counts[-MAX_POINTS:]
    update_graph(x_data,y_data)

    # Display Dashboard Information

    print("\n========== IDS DASHBOARD ==========")

    print(
        f"Total Packets       : {total_packets}"
    )
    print(
        f"Suspicious Alerts   : {suspicious_packets}"
    )
    print(
        f"Unique IPs Detected : {len(unique_ips)}"
    )

# Function: add_port()
#
# Purpose:
#     Stores packet statistics for
#     destination ports.

def add_port(port):

    port_counter[port] += 1

# Function: add_recent_alert()
#
# Purpose:
#     Stores the latest IDS alerts.

def add_recent_alert(time, src_ip, attack, port):

    recent_alerts.append(

        (
          time,
            src_ip,
            attack,
            port
        )
    )

    # Keep only the latest 10 alerts.
    if len(recent_alerts) > 10:

        recent_alerts.pop(0)

# Function: increase_blocked_ip()
#
# Purpose:
#     Increases the blocked IP counter.

def increase_blocked_ip():

    global blocked_ips

    blocked_ips += 1

# Function: get_dashboard_data()
#
# Purpose:
#     Returns all dashboard statistics.

def get_dashboard_data():

    return {

        "total_packets": total_packets,

        "suspicious_packets": suspicious_packets,

        "blocked_ips": blocked_ips,

        "unique_ips": len(unique_ips),

        "packet_counts": packet_counts,

        "alert_counts": alert_counts,

        "port_counter": port_counter,

        "ip_counter": ip_counter,

        "recent_alerts": recent_alerts

    }
