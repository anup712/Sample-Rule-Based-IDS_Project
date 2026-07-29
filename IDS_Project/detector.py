# IP BLOCKING MODULE

# This file is responsible for:
# 1. Keeping track of blocked IP addresses.
# 2. Saving blocked IPs to a text file.
# 3. Preventing the same IP from being blocked multiple times.
# 4. Updating the IDS dashboard when an IP is blocked.

# Import Required Modules
# Import the function that updates
# the blocked IP counter on the dashboard.
from dashboard import increase_blocked_ip

# File Path

# Name and location of the file where blocked IP addresses
# will be permanently stored.
BLOCK_FILE = "data/blocked_ips.txt"

# Global Variables

# A set is used to store blocked IP addresses.
# A set automatically removes duplicate values,
# so the same IP cannot be blocked more than once.
blocked_ips = set()

# Function: block_ip()
#
# Purpose:
#     Blocks a suspicious IP address by:
#     1. Adding it to the blocked IP list.
#     2. Saving it in a text file.
#     3. Updating the dashboard.
#     4. Displaying a confirmation message.

def block_ip(ip):

    # Check whether the IP address has already been blocked.
    # This prevents duplicate entries in both memory and the file.
    if ip not in blocked_ips:

        # Add the IP address to the set of blocked IPs.
        blocked_ips.add(ip)

        # Increase the blocked IP counter
        # displayed on the dashboard.
        increase_blocked_ip()

        # Open the blocked IP file in Append ("a") mode.
        # Append mode adds new data to the end of the file
        # without deleting the existing contents.
        with open(BLOCK_FILE, "a") as file:

            # Write the blocked IP address to the file.
            # "\n" moves the next IP to a new line.
            file.write(ip + "\n")

        # Display a confirmation message.
        print("\n====================================")
        print("      IP BLOCKED SUCCESSFULLY")
        print("====================================")
        print(f"Blocked IP Address : {ip}")
        print(f"Total Blocked IPs  : {len(blocked_ips)}")
        print("====================================")
