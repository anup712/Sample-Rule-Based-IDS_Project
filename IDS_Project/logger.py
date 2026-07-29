# ALERT LOGGING MODULE

# This file is responsible for:
# 1. Recording all detected attacks in a log file.
# 2. Saving suspicious IP addresses.
# 3. Adding a timestamp to every alert.

# These logs help administrators review attacks
# and investigate suspicious network activity later.

# Import Required Library

# Import the datetime class.
# It is used to get the current date and time
# whenever an attack is detected.
from datetime import datetime

# File Paths

# File used to store detailed attack logs.
# Each alert will include the time, IP address,
# attack type, and destination port.
LOG_FILE = "logs/alerts.log"

# File used to store only suspicious IP addresses.
# This can be used later for blocking or analysis.
IP_FILE = "data/suspicious_ips.txt"

# Function: log_alert()
# Purpose:
#     Saves information about a detected attack.
#
# Parameters:
#     src_ip      -> Source IP address of the attacker.
#     port        -> Network port involved in the attack.
#     attack_name -> Name/type of the detected attack.


def log_alert(src_ip, port, attack_name):

    # Get Current Date and Time
    # Generate the current timestamp.
    # Example:
    # 2026-07-28 14:35:12
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Create Alert Message
    # Build a formatted alert message that contains:
    # • Timestamp
    # • Attack name
    # • Source IP address
    # • Port number

    # Example:
    # [2026-07-28 14:35:12] ALERT: Port Scan detected |
    # IP: 192.168.1.5 | PORT: 22
    alert_message = (
        f"[{timestamp}] "
        f"ALERT: {attack_name} detected | "
        f"IP: {src_ip} | "
        f"PORT: {port}\n"
    )

    # Save Alert to Log File
    # Open the alert log file in Append ("a") mode.
    # Append mode adds new alerts without deleting
    # any existing log entries.
    with open(LOG_FILE, "a") as file:
        # Write the alert message to the log file.
        file.write(alert_message)
    # Save Suspicious IP Address
    # Open the suspicious IP file in Append ("a") mode.
    with open(IP_FILE, "a") as file:
        # Save only the source IP address.
        # "\n" places each IP on a new line.
        file.write(src_ip + "\n")
