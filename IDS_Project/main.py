# MAIN PROGRAM

# This is the starting point of the Intrusion Detection System (IDS).
#
# Responsibilities:
# 1. Start the GUI Dashboard.
# 2. Start live packet capturing.
# 3. Run packet capture and GUI at the same time.
# 4. Handle program termination safely.

# Import Required Modules

# Import the function that starts live packet capture.
from packet_capture import start_capture

# Import the function that starts the graphical user interface (GUI).
from gui import start_gui

# Import Python's threading module.
# Threading allows multiple tasks to run at the same time.
import threading


# Main Program Execution

try:

    # Display a message indicating that the IDS has started.
    print("========== Python IDS Started ==========")

    # Create a Separate Thread for Packet Capture
    # Create a new thread that runs packet capturing.
    # The daemon=True option automatically stops
    # the thread when the main program exits.
    capture_thread = threading.Thread(
        target=start_capture,
        daemon=True
    )

    # Start live packet capturing.
    capture_thread.start()
    # Start the IDS Dashboard.
    #
    # The GUI must always run in the main thread.
    start_gui()

# Handle Program Termination
# KeyboardInterrupt occurs when the user presses Ctrl + C.
except KeyboardInterrupt:
    # Display a shutdown message.
    print("\nStopping IDS...")
    print("IDS Stopped Successfully.")
