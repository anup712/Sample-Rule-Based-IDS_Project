# PACKET CAPTURE MODULE

# This module is responsible for:
# 1. Capturing live network packets.
# 2. Extracting important packet information.
# 3. Detecting traffic on suspicious ports.
# 4. Logging alerts.
# 5. Blocking suspicious IP addresses.
# 6. Updating the IDS dashboard.
# 7. Collecting statistics for live graphs.
# 8. Recording recent IDS alerts.

# Import Required Libraries
# Import Scapy functions and protocol layers.
# sniff() captures live network packets.
# IP, TCP and UDP allow us to inspect protocol headers.
from scapy.all import sniff, IP, TCP, UDP

# Used to generate timestamps for packets.
from datetime import datetime

# Used to print colored messages in the terminal.
from colorama import Fore, Style

# Import the function that saves attack logs.
from logger import log_alert

# Import dashboard functions.
from dashboard import (
    update_dashboard,
    add_port,
    add_recent_alert
)

# Import the function that blocks suspicious IP addresses.
from detector import block_ip

# Global Variables
# Stores the total number of packets captured.
packet_count = 0

# Suspicious Ports Dictionary
# These ports are commonly targeted by attackers or are
# frequently monitored in Intrusion Detection Systems.
# Key   = Port Number
# Value = Service Name

suspicious_ports = {

    # Remote Access
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "TELNET",

    # Email
    25: "SMTP",
    110: "POP3",
    143: "IMAP",

    # Web Services
    80: "HTTP",
    8080: "HTTP Alternate",

    # DNS
    53: "DNS",

    # DHCP
    67: "DHCP Server",
    68: "DHCP Client",

    # File Sharing
    69: "TFTP",
    135: "RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    445: "SMB",

    # Directory Services
    389: "LDAP",
    636: "LDAPS",

    # Database
    1433: "Microsoft SQL",
    1521: "Oracle",
    3306: "MySQL",
    5432: "PostgreSQL",

    # Remote Desktop
    3389: "RDP",

    # VPN
    500: "IKE",
    1701: "L2TP",
    1723: "PPTP",

    # Monitoring
    161: "SNMP",
    162: "SNMP Trap",

    # Remote Management
    5900: "VNC",

    # Printing
    515: "LPD",
    631: "IPP"
}

# Function: process_packet()
# Purpose:
#     Processes every captured packet.
# Responsibilities:
#     • Count packets
#     • Extract packet information
#     • Detect suspicious ports
#     • Generate alerts
#     • Block attacker IP
#     • Update dashboard
#     • Collect graph statistics

def process_packet(packet):

    # Tell Python that packet_count refers to
    # the global variable declared above.
    global packet_count

    # Increase the packet counter.
    packet_count += 1

    # Generate the current time.
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Check whether the packet contains an IP layer.
    # Non-IP packets are ignored.
    if packet.haslayer(IP):

        # Extract the source IP address.
        src_ip = packet[IP].src

        # Extract the destination IP address.
        dst_ip = packet[IP].dst

        # Default protocol.
        protocol = "OTHER"

        # Default destination port.
        port = "N/A"

        # Default attack name.
        attack_name = "Normal Traffic"

        # Assume the packet is not suspicious.
        is_suspicious = False

        # Detect Transport Layer Protocol
        # Check if the packet uses TCP.
        if packet.haslayer(TCP):
            # Save protocol name.
            protocol = "TCP"
            # Extract destination port.
            port = packet[TCP].dport
        # Otherwise check for UDP.
        elif packet.haslayer(UDP):
            # Save protocol name.
            protocol = "UDP"
            # Extract destination port.
            port = packet[UDP].dport

        # Store Packet Statistics
        # Count packets received on each destination port.
        if port != "N/A":

            add_port(port)

        # Display Packet Information

        print(f"\n[{timestamp}] Packet #{packet_count}")
        print(f"Source IP         : {src_ip}")
        print(f"Destination IP    : {dst_ip}")
        print(f"Protocol          : {protocol}")
        print(f"Destination Port  : {port}")

        # Detect Suspicious Ports

        if port in suspicious_ports:

            # Retrieve the attack/service name.
            attack_name = suspicious_ports[port]

            # Mark packet as suspicious.
            is_suspicious = True

            # Display a red alert.
            print(
                Fore.RED +
                f"\n🚨 ALERT: Suspicious Service Detected ({attack_name})"
            )

            print(f"Source IP : {src_ip}")
            print(f"Port      : {port}")

            # Restore the terminal color.
            print(Style.RESET_ALL)

            # Save the alert to the log file.
            log_alert(src_ip, port, attack_name)

            # Block the attacker's IP.
            block_ip(src_ip)
          
        # Save Recent Alert Information
        # Save only suspicious packets in the
        # Recent Alerts list.
        if is_suspicious:
            add_recent_alert(
                timestamp,
                src_ip,
                attack_name,
                port
            )

        # Update Dashboard
        # Send the latest statistics to the dashboard.
        update_dashboard(
            src_ip,
            is_suspicious
        )

        # Display Dashboard Information

        print("\n----------------------------------------")
        print("Packet Successfully Processed")
        print("----------------------------------------")

# Function: start_capture()
# Purpose:
#     Starts live packet capturing.
# Responsibilities:
#     • Capture live packets.
#     • Send every packet to process_packet().
#     • Prevent packets from being stored in memory.

def start_capture():
    # Display a startup message.
    print("\n========================================")
    print("     LIVE PACKET CAPTURE STARTED")
    print("========================================")
    print("Monitoring network traffic...")
    print("Press Ctrl + C to stop the IDS.")
    print("========================================\n")

    # Start capturing packets.
    sniff(
        prn=process_packet,
        store=False
    )
