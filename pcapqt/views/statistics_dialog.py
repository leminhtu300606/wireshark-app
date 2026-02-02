# -*- coding: utf-8 -*-
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, 
    QHeaderView, QPushButton, QLabel, QMessageBox, QWidget, QSplitter
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QBrush

import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import time
from datetime import datetime

class MplCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = self.fig.add_subplot(111)
        # Style the chart
        self.axes.set_facecolor('#f0f0f0')
        self.fig.patch.set_facecolor('#f0f0f0')
        self.axes.grid(True, linestyle='--', alpha=0.6)
        
        super(MplCanvas, self).__init__(self.fig)

class StatisticsDialog(QDialog):
    def __init__(self, ip_stats, blocked_ips, block_callback, unblock_callback, parent=None):
        super().__init__(parent)
        self.setWindowTitle("IP Traffic Statistics & Analysis")
        self.setMinimumSize(900, 700)
        
        # Data references
        self.ip_stats = ip_stats
        self.blocked_ips = blocked_ips
        self.block_callback = block_callback
        self.unblock_callback = unblock_callback
        
        # Setup UI
        self.layout = QVBoxLayout(self)
        
        # Splitter for Chart (top) and Table (bottom)
        splitter = QSplitter(Qt.Vertical)
        
        # Top: Chart Section
        chart_widget = QWidget()
        chart_layout = QVBoxLayout(chart_widget)
        
        chart_header = QLabel("Real-time Traffic (Requests/sec)")
        chart_header.setStyleSheet("font-size: 14px; font-weight: bold; color: #333;")
        chart_layout.addWidget(chart_header)
        
        self.canvas = MplCanvas(self, width=5, height=4, dpi=100)
        chart_layout.addWidget(self.canvas)
        splitter.addWidget(chart_widget)
        
        # Bottom: Table Section
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        
        # Table Header & Controls
        header_layout = QHBoxLayout()
        header_label = QLabel("Source IP Analysis")
        header_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #333;")
        header_layout.addWidget(header_label)
        
        # Block Input (Direct)
        # self.block_input = QLineEdit()
        # self.block_input.setPlaceholderText("Enter IP to block...")
        # header_layout.addWidget(self.block_input)
        
        header_layout.addStretch()
        
        self.toggle_block_btn = QPushButton("🚫 Block / Unblock Selected")
        self.toggle_block_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF5252; color: white; padding: 6px 12px;
                border-radius: 4px; font-weight: bold;
            }
            QPushButton:hover { background-color: #D32F2F; }
        """)
        self.toggle_block_btn.clicked.connect(self.toggle_block_ip)
        header_layout.addWidget(self.toggle_block_btn)
        
        table_layout.addLayout(header_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["State", "IP Address", "Source Name / Device", "Total Requests", "Last Seen"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents) # State icon
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents) # IP
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)          # Name
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents) # Count
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents) # Time
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setAlternatingRowColors(True)
        table_layout.addWidget(self.table)
        
        splitter.addWidget(table_widget)
        self.layout.addWidget(splitter)
        
        # Set initial splitter sizes (40% chart, 60% table)
        splitter.setSizes([300, 400])
        
        # Footer
        footer_layout = QHBoxLayout()
        self.status_label = QLabel(f"Total IPs: 0 | Blocked: {len(self.blocked_ips)}")
        footer_layout.addWidget(self.status_label)
        footer_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        footer_layout.addWidget(close_btn)
        
        self.layout.addLayout(footer_layout)
        
        # Timer for live updates
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_ui)
        self.update_timer.start(1000) # Update every second
        
        # Initial draw
        self.update_ui()

    def update_ui(self):
        """Refresh chart and table data."""
        self.update_table()
        self.update_chart()
        self.status_label.setText(f"Total IPs: {len(self.ip_stats)} | Blocked: {len(self.blocked_ips)}")

    def update_table(self):
        """Update the table with latest stats."""
        # Save current selection to restore after update
        selected_ip = None
        current_row = self.table.currentRow()
        if current_row >= 0:
            item = self.table.item(current_row, 1)
            if item:
                selected_ip = item.text()
        
        # Sort IPs by count (descending)
        sorted_ips = sorted(self.ip_stats.items(), key=lambda x: x[1]['count'], reverse=True)
        
        self.table.setRowCount(len(sorted_ips))
        
        for row, (ip, data) in enumerate(sorted_ips):
            # 0: State (Blocked/Active)
            is_blocked = ip in self.blocked_ips
            state_item = QTableWidgetItem("⛔" if is_blocked else "✅")
            state_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 0, state_item)
            
            # 1: IP
            self.table.setItem(row, 1, QTableWidgetItem(ip))
            
            # 2: Name
            name = data.get('name', '') or data.get('device', '') or "Resolving..."
            self.table.setItem(row, 2, QTableWidgetItem(name))
            
            # 3: Count
            count_item = QTableWidgetItem(str(data['count']))
            count_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 3, count_item)
            
            # 4: Last Seen
            last_timestamp = data.get('last_seen', 0)
            if last_timestamp:
                time_str = datetime.fromtimestamp(last_timestamp).strftime('%H:%M:%S')
            else:
                time_str = "-"
            self.table.setItem(row, 4, QTableWidgetItem(time_str))
            
            # Color blocked rows
            if is_blocked:
                for col in range(5):
                    item = self.table.item(row, col)
                    item.setBackground(QColor("#FFEBEE")) # Light red
        
        # Restore selection
        if selected_ip:
            items = self.table.findItems(selected_ip, Qt.MatchExactly)
            if items:
                # Find the item that is in the IP column (1)
                for item in items:
                    if item.column() == 1:
                        self.table.setCurrentItem(item)
                        break

    def update_chart(self):
        """Update matplotlib chart with top traffic sources."""
        self.canvas.axes.clear()
        
        # We want to show requests per second for the top 5 active IPs
        # For simplicity in this version, we will plot the 'count' growth or recent history
        # A better metric for 'real-time' is requests in the last N seconds
        
        current_time = time.time()
        # Filter for top 5 IPs by total count
        top_ips = sorted(self.ip_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:5]
        
        for ip, data in top_ips:
            history = data.get('history', [])
            # Filter history to last 60 seconds for the chart
            recent_history = [t for t in history if current_time - t <= 60]
            
            # Group into 1-second bins
            bins = {} # relative_second -> count
            for t in recent_history:
                sec = int(current_time - t)
                bins[sec] = bins.get(sec, 0) + 1
            
            # Create x, y arrays (X is seconds ago, 60 down to 0)
            x_vals = list(range(60))
            y_vals = [bins.get(sec, 0) for sec in x_vals]
            
            # Reverse for plotting (0 on right is now)
            # Actually easier to plot time relative to now
            # Let's plot: X-axis = Time (Seconds ago), Y-axis = Requests/sec
            
            name = data.get('name') or ip
            if len(name) > 15: name = name[:12] + "..."
            
            self.canvas.axes.plot(x_vals, y_vals, label=name)
        
        self.canvas.axes.set_xlim(60, 0) # 60 seconds ago to Now
        self.canvas.axes.set_xlabel('Seconds Ago')
        self.canvas.axes.set_ylabel('Packets / Sec')
        self.canvas.axes.set_title('Live Traffic (Top 5 Sources)')
        self.canvas.axes.legend(loc='upper left', fontsize='small')
        self.canvas.axes.grid(True, linestyle=':', alpha=0.6)
        
        self.canvas.draw()

    def toggle_block_ip(self):
        """Block or Unblock the currently selected IP."""
        current_row = self.table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Selection", "Please select an IP address from the list.")
            return
            
        ip_item = self.table.item(current_row, 1)
        if not ip_item:
            return
            
        ip = ip_item.text()
        
        if ip in self.blocked_ips:
            # Unblock
            self.unblock_callback(ip)
            QMessageBox.information(self, "Unblocked", f"IP {ip} has been unblocked.")
        else:
            # Block
            self.block_callback(ip)
            QMessageBox.information(self, "Blocked", f"IP {ip} has been blocked.\nFuture packets from this IP will be ignored.")
        
        self.update_table()
