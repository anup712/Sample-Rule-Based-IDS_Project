# GUI MODULE

# This file creates the Graphical User Interface (GUI)
# for the Intrusion Detection System (IDS).
#
# Responsibilities:
# 1. Display IDS statistics.
# 2. Display live graphs.
# 3. Display recent IDS alerts.
# 4. Update the dashboard in real time.
# 5. Provide a professional monitoring interface.

# Import Required Libraries
# Import the Tkinter library.
# Tkinter is Python's built-in library used
# to create graphical user interfaces.
import tkinter as tk

# Import ttk.
# ttk provides modern widgets such as Treeview.
from tkinter import ttk

# Import Figure from Matplotlib.
# Figure is used to create graphs.
from matplotlib.figure import Figure

# Import FigureCanvasTkAgg.
# This allows Matplotlib graphs to be displayed
# inside the Tkinter window.
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Global Variables
# Main application window.
window = None

# Statistics Cards

packet_label = None
alert_label = None
ip_label = None
blocked_label = None

# Graph Objects

figure = None
activity_ax = None
alerts_ax = None
ports_ax = None
ips_ax = None
activity_line = None
alerts_line = None
canvas = None

# Recent Alerts Table
alerts_table = None

# Status Bar
status_label = None

# Dashboard Colors
BACKGROUND = "#1E1E1E"
CARD = "#2C2C2C"
TITLE = "white"
TEXT = "white"
STATUS = "lightgreen"

# Function: create_stat_card()
#
# Purpose:
#     Creates one dashboard statistics card.

def create_stat_card(parent, title, value):

    # Create the card frame.
    frame = tk.Frame(
        parent,
        bg=CARD,
        bd=2,
        relief="ridge"
    )

    # Create the title.
    heading = tk.Label(
        frame,
        text=title,
        bg=CARD,
        fg="cyan",
        font=("Arial", 11, "bold")
    )
    heading.pack(
        pady=(8, 2)
    )

    # Create the value label.
    value_label = tk.Label(
        frame,
        text=value,
        bg=CARD,
        fg=TEXT,
        font=("Arial", 18, "bold")
    )
    value_label.pack(
        pady=(0, 10)
    )

    return frame, value_label

# Function: start_gui()
#
# Purpose:
#     Creates the IDS Dashboard window.

def start_gui():

    global window

    global packet_label
    global alert_label
    global ip_label
    global blocked_label

    global figure
    global activity_ax
    global alerts_ax
    global ports_ax
    global ips_ax

    global activity_line
    global alerts_line

    global canvas
    global alerts_table
    global status_label

    # Create Main Window

    window = tk.Tk()
    window.title(
        "Python Intrusion Detection System"
    )

    window.geometry("1400x900")
    window.minsize(300, 200)

    window.configure(bg=BACKGROUND)

    # Allow rows to resize properly
    window.grid_rowconfigure(2, weight=3)   # Graph section
    window.grid_rowconfigure(3, weight=1)   # Recent alerts
    window.grid_columnconfigure(0, weight=1)
    
    # Dashboard Title
    
    title = tk.Label(

        window,
        text="PYTHON INTRUSION DETECTION SYSTEM",
        bg=BACKGROUND,
        fg=TITLE,
        font=("Arial", 22, "bold")
    )
    title.grid(
        row=0,
        column=0,
        columnspan=4,
        pady=20
    )
    
    # Statistics Section
    stats_frame = tk.Frame(
        window,
        bg=BACKGROUND
    )
    stats_frame.grid(
        row=1,
        column=0,
        columnspan=4,
        padx=15,
        pady=10,
        sticky="ew"
    )
    stats_frame.columnconfigure(
        (0,1,2,3),
        weight=1
    )

    # Total Packets Card
    packet_card, packet_label = create_stat_card(
        stats_frame,
        "Total Packets",
        "0"
    )
    packet_card.grid(
        row=0,
        column=0,
        padx=8,
        sticky="nsew"
    )

    # Alerts Card

    alert_card, alert_label = create_stat_card(
        stats_frame,
        "Suspicious Alerts",
        "0"
    )
    alert_card.grid(
        row=0,
        column=1,
        padx=8,
        sticky="nsew"
    )
    
    # Unique IPs Card
    ip_card, ip_label = create_stat_card(
        stats_frame,
        "Unique IPs",
        "0"
    )
    ip_card.grid(
        row=0,
        column=2,
        padx=8,
        sticky="nsew"
    )

    # Blocked IPs Card
    blocked_card, blocked_label = create_stat_card(
        stats_frame,
        "Blocked IPs",
        "0"
    )
    blocked_card.grid(
        row=0,
        column=3,
        padx=8,
        sticky="nsew"
    )

    # Create Graph Section
    # Create a frame that will contain
    # all four live graphs.
    graph_frame = tk.Frame(
        window,
        bg=BACKGROUND
    )
    graph_frame.grid(
        row=2,
        column=0,
        columnspan=4,
        padx=15,
        pady=10,
        sticky="nsew"
    )

    # Allow the graph frame to expand.
    graph_frame.rowconfigure(0, weight=1)
    graph_frame.rowconfigure(1, weight=1)
    graph_frame.columnconfigure(0, weight=1)
    graph_frame.columnconfigure(1, weight=1)

    # Create the Matplotlib Figure
    # Create one figure that contains
    # four different graphs.
    figure = Figure(
    figsize=(11, 5.5),
    dpi=100
    )

    # Graph 1
    # Live Network Activity

    activity_ax = figure.add_subplot(221)
    activity_line, = activity_ax.plot(
        [],
        [],
        linewidth=2,
        color="blue"
    )
    activity_ax.set_title(
        "Live Network Activity"
    )
    activity_ax.set_xlabel(
        "Packets"
    )
    activity_ax.set_ylabel(
        "Total"
    )
    activity_ax.grid(True)

    # Graph 2
    # Alerts Over Time
    alerts_ax = figure.add_subplot(222)
    alerts_line, = alerts_ax.plot(
        [],
        [],
        linewidth=2,
        color="red"
    )
    alerts_ax.set_title(
        "Alerts Over Time"
    )
    alerts_ax.set_xlabel(
        "Alerts"
    )
    alerts_ax.set_ylabel(
        "Count"
    )
    alerts_ax.grid(True)
    
    # Graph 3
    # Packets Per Port

    ports_ax = figure.add_subplot(223)
    ports_ax.set_title(
        "Packets Per Port"
    )
    ports_ax.set_xlabel(
        "Port"
    )
    ports_ax.set_ylabel(
        "Packets"
    )
    ports_ax.grid(True)
    
    # Graph 4
    # Top Source IPs
    ips_ax = figure.add_subplot(224)
    ips_ax.set_title(
        "Top Source IPs"
    )
    ips_ax.set_xlabel(
        "Source IP"
    )
    ips_ax.set_ylabel(
        "Packets"
    )
    ips_ax.grid(True)

    # Display Figure Inside Tkinter

    canvas = FigureCanvasTkAgg(
        figure,
        master=graph_frame
    )
    canvas.draw()    
    canvas.get_tk_widget().pack(
    fill=tk.BOTH,
    expand=False
    )

    # Create Recent Alerts Section
    # Create a frame for displaying
    # the latest IDS alerts.
    table_frame = tk.Frame(
        window,
        bg=BACKGROUND
    )
    table_frame.grid(
        row=3,
        column=0,
        columnspan=4,
        padx=15,
        pady=10,
        sticky="nsew"
    )

    # Create the section title.
    table_title = tk.Label(
        table_frame,
        text="Recent Alerts",
        bg=BACKGROUND,
        fg="white",
        font=("Arial", 16, "bold")
    )
    table_title.pack(
        anchor="w",
        pady=(0, 5)
    )

    # Create Recent Alerts Table
    alerts_table = ttk.Treeview(
        table_frame,
        columns=(
            "Time",
            "Source IP",
            "Attack",
            "Port"
        ),
        show="headings",
        height=8
    )

    # Configure each column.
    alerts_table.heading(
        "Time",
        text="Time"
    )
    alerts_table.heading(
        "Source IP",
        text="Source IP"
    )
    alerts_table.heading(
        "Attack",
        text="Attack Type"
    )
    alerts_table.heading(
        "Port",
        text="Port"
    )
    alerts_table.column(
        "Time",
        width=120,
        anchor="center"
    )
    alerts_table.column(
        "Source IP",
        width=250,
        anchor="center"
    )
    alerts_table.column(
        "Attack",
        width=220,
        anchor="center"
    )
    alerts_table.column(
        "Port",
        width=120,
        anchor="center"
    )
    alerts_table.pack(
        fill=tk.BOTH,
        expand=True
    )

    # Status Bar
    status_label = tk.Label(
        window,
        text="🟢 Status : Monitoring",
        bg=BACKGROUND,
        fg=STATUS,
        font=("Arial", 12, "bold")
    )
    status_label.grid(
        row=4,
        column=0,
        columnspan=4,
        pady=10
    )

    # Start the GUI Event Loop
    window.mainloop()

# Function: update_gui()
# Purpose:
#     Updates the dashboard statistics.

def update_gui(
    packets,
    alerts,
    ips
):
    if window is None:
        return
    def refresh():
        packet_label.config(
            text=str(
                packets
            )
        )
        alert_label.config(
            text=str(
                alerts
            )
        )
        ip_label.config(
            text=str(
                ips
            )
        )
    window.after(
        0,
        refresh
    )

# Function: update_graph()
# Purpose:
#     Updates the Live Network Activity graph.

def update_graph(
    x_data,
    y_data
):
    if window is None:
        return
    def refresh():
        activity_line.set_data(
            x_data,
            y_data
        )
        activity_ax.relim()
        activity_ax.autoscale_view()
        canvas.draw_idle()
    window.after(
        0,
        refresh
    )

# Function: update_blocked_ips()
# Purpose:
#     Updates the Blocked IPs card.

def update_blocked_ips(
    blocked_count
):
    if window is None:
        return
    def refresh():
        blocked_label.config(
            text=str(
                blocked_count
            )
        )
    window.after(
        0,
        refresh
    )

# Function: update_recent_alerts()
# Purpose:
#     Displays the latest alerts
#     inside the Recent Alerts table.

def update_recent_alerts(
    alerts
):
    if window is None:
        return
    def refresh():
        # Remove old rows.
        for row in alerts_table.get_children():
            alerts_table.delete(
                row
            )
        # Display the latest alerts.
        for alert in alerts:
            alerts_table.insert(
                "",
                tk.END,
                values=alert
            )
    window.after(
        0,
        refresh
    )

# Function: update_alert_graph()

# Purpose:
#     Updates the Alerts Over Time graph.

def update_alert_graph(x_data, y_data):

    # Check whether the GUI exists.
    if window is None:
        return

    # Create a refresh function.
    def refresh():

        # Update the graph.
        alerts_line.set_data(
            x_data,
            y_data
        )
        # Recalculate graph limits.
        alerts_ax.relim()
        # Automatically resize.
        alerts_ax.autoscale_view()
        # Redraw the canvas.
        canvas.draw_idle()
    # Schedule the update.
    window.after(
        0,
        refresh
    )

# Function: update_port_graph()

# Purpose:
#     Updates the Packets Per Port graph.

def update_port_graph(port_data):
    # Check whether the GUI exists.
    if window is None:
        return
    def refresh():
        # Clear previous graph.
        ports_ax.clear()
        # Set graph title.
        ports_ax.set_title(
            "Packets Per Port"
        )
        # Set X-axis label.
        ports_ax.set_xlabel(
            "Port"
        )
        # Set Y-axis label.
        ports_ax.set_ylabel(
            "Packets"
        )
        # Display grid lines.
        ports_ax.grid(True)
        # Check whether data exists.
        if len(port_data) > 0:
            # Convert dictionary to lists.
            ports = list(
                port_data.keys()
            )
            counts = list(
                port_data.values()
            )
            # Draw bar chart.
            ports_ax.bar(
                ports,
                counts
            )
        # Refresh canvas.
        canvas.draw_idle()
    # Schedule graph update.
    window.after(
        0,
        refresh
    )

# Function: update_ip_graph()
# Purpose:
#     Updates the Top Source IPs graph.

def update_ip_graph(ip_data):
    # Check whether the GUI exists.
    if window is None:
        return
    def refresh():
        # Clear previous graph.
        ips_ax.clear()
        # Set graph title.
        ips_ax.set_title(
            "Top Source IPs"
        )
        # Set labels.
        ips_ax.set_xlabel(
            "Source IP"
        )
        ips_ax.set_ylabel(
            "Packets"
        )
        # Display grid.
        ips_ax.grid(True)
        # Check whether data exists.
        if len(ip_data) > 0:
            # Display only Top 10 IPs.
            top_ips = dict(
                sorted(
                    ip_data.items(),
                    key=lambda item: item[1],
                    reverse=True
                )[:10]
            )
            # Draw bar chart.
            ips_ax.bar(
                list(top_ips.keys()),
                list(top_ips.values())
            )
            # Rotate labels.
            ips_ax.tick_params(
                axis="x",
                rotation=45
            )
        # Refresh canvas.
        canvas.draw_idle()
    # Schedule GUI update.
    window.after(
        0,
        refresh
    )

# Function: reset_dashboard()
# Purpose:
#     Clears all dashboard information.

def reset_dashboard():
    # Check whether the GUI exists.
    if window is None:
        return
    # Reset dashboard labels.
    packet_label.config(text="0")
    alert_label.config(text="0")
    ip_label.config(text="0")
    blocked_label.config(text="0")
    # Clear graphs.
    activity_ax.clear()
    alerts_ax.clear()
    ports_ax.clear()
    ips_ax.clear()
    # Clear Recent Alerts table.
    for row in alerts_table.get_children():
        alerts_table.delete(
            row
        )
    # Refresh the canvas.
    canvas.draw_idle()
