# -*- coding: utf-8 -*-

from PyQt5.QtWidgets import (
    QMainWindow, QLineEdit, QLabel, QMenu, QAction, QMessageBox,
    QComboBox, QInputDialog, QPushButton, QDialog, QVBoxLayout,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtCore import QTimer, Qt, QMutex, QMutexLocker
from PyQt5.QtGui import QFont
from scapy.all import TCP, UDP, IP, Ether
import traceback
from collections import defaultdict

from ..ui_pcapqt import Ui_PcapQt
from ..models.packet_table_model import PacketTableModel
from ..models.packet_detail_model import PacketDetailModel
from ..models.packet_filter_model import PacketFilterModel
from ..threads.sniffer_thread import SnifferThread
from ..utils.packet_parser import PacketParser
from ..utils.stream_analyzer import StreamAnalyzer
from .interface_dialog import InterfaceDialog
from .stream_dialog import StreamDialog
from .statistics_dialog import StatisticsDialog
import time

class PcapQt(QMainWindow):

    def __init__(self):
        super().__init__()
        self.ui = Ui_PcapQt()
        self.ui.setupUi(self)
        
        # Selected interface
        self.selected_interface = None

        # Packet models
        self.packet_model = PacketTableModel()
        self.detail_model = PacketDetailModel()
        
        # Filter proxy model
        self.filter_model = PacketFilterModel()
        self.filter_model.setSourceModel(self.packet_model)

        # Set models to views
        self.ui.packageTableView.setModel(self.filter_model)
        self.ui.detailedPackageTableView.setModel(self.detail_model)

        # Configure package table view
        self.ui.packageTableView.horizontalHeader().setStretchLastSection(True)
        self.ui.packageTableView.setSelectionBehavior(self.ui.packageTableView.SelectRows)
        self.ui.packageTableView.setSelectionMode(self.ui.packageTableView.SingleSelection)
        self.ui.packageTableView.setAlternatingRowColors(True)
        
        # Set fixed row height for better scrolling performance (lazy loading optimization)
        self.ui.packageTableView.verticalHeader().setDefaultSectionSize(22)
        self.ui.packageTableView.verticalHeader().setSectionResizeMode(self.ui.packageTableView.verticalHeader().Fixed)
        
        # Enable context menu for package table
        self.ui.packageTableView.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.packageTableView.customContextMenuRequested.connect(self.show_context_menu)

        # Configure detail table view
        self.ui.detailedPackageTableView.horizontalHeader().setStretchLastSection(True)
        self.ui.detailedPackageTableView.verticalHeader().setVisible(False)
        self.ui.detailedPackageTableView.setAlternatingRowColors(True)

        # Sniffer thread
        self.sniffer = SnifferThread()
        # Use QueuedConnection for thread-safe signal handling
        self.sniffer.packet_captured.connect(self.on_packet_captured, Qt.QueuedConnection)
        self.sniffer.capture_error.connect(self.on_capture_error, Qt.QueuedConnection)
        
        # Packet queue for batched processing
        self.packet_queue = []
        self.packet_queue_mutex = QMutex()
        
        # Batch update timer (reduces UI updates)
        self.batch_timer = QTimer()
        self.batch_timer.timeout.connect(self.process_packet_queue)
        self.batch_timer.start(100)  # Process queue every 100ms for better performance
        
        # Packet limit (0 = unlimited)
        self.packet_limit = 0
        self.PACKET_LIMIT_OPTIONS = {
            'Unlimited': 0,
            '10,000': 10000,
            '20,000': 20000,
            '50,000': 50000,
            'Custom...': -1  # Special value to trigger input dialog
        }
        
        # Filter debounce timer (delays filter application for smoother typing)
        self.filter_debounce_timer = QTimer()
        self.filter_debounce_timer.setSingleShot(True)
        self.filter_debounce_timer.timeout.connect(self._apply_debounced_filter)
        self._pending_filter_text = ""

        # State variables
        self.raw_packets = []
        self.current_packet_index = -1
        self.auto_scroll_enabled = True
        self.ui.detailButton.setChecked(False)

        # Scroll handling - track last scroll position for direction detection
        self.last_scroll_value = 0
        scrollbar = self.ui.packageTableView.verticalScrollBar()
        scrollbar.valueChanged.connect(self.on_scroll_changed)
        
        # Click detection for stopping autoscroll
        self.ui.packageTableView.clicked.connect(self.on_packet_clicked)
        
        self.scroll_check_timer = QTimer()
        self.scroll_check_timer.timeout.connect(self.check_if_at_bottom)
        self.scroll_check_timer.start(100)

        # Setup filter bar and packet limit dropdown
        self.setup_filter_bar()
        self.setup_packet_limit_dropdown()

        # Connect signals
        self.ui.startCapture.toggled.connect(self.toggle_capture)
        self.ui.restartButton.clicked.connect(self.restart_capture)
        self.ui.packageTableView.selectionModel().currentRowChanged.connect(self.on_packet_selected)
        self.ui.previousPakageButton.clicked.connect(self.go_to_previous)
        self.ui.nextPakageButton.clicked.connect(self.go_to_next)
        self.ui.firstPakageButton.clicked.connect(self.go_to_first)
        self.ui.lastPakageButton.clicked.connect(self.go_to_last)
        
        # Show interface selection dialog on startup
        QTimer.singleShot(100, self.show_interface_dialog)
        
        # Setup IP statistics tracking
        self.setup_ip_statistics()
    
    
    def setup_ip_statistics(self):
        """Setup IP request statistics tracking and button."""
        # Track detailed stats per IP: { 'ip': { 'count': 0, 'name': '', 'last_seen': t, 'history': [] } }
        self.ip_stats = {}
        # Blocked IPs set
        self.blocked_ips = set()
        
        # Statistics button in toolbar
        self.stats_btn = QPushButton("📊 IP Stats")
        self.stats_btn.setStyleSheet(
            "QPushButton { background-color: #E3F2FD; color: #1565C0; padding: 4px 12px; "
            "border-radius: 4px; font-weight: bold; }"
            "QPushButton:hover { background-color: #BBDEFB; }"
        )
        self.stats_btn.clicked.connect(self.show_ip_statistics)
        self.ui.horizontalLayout.addWidget(self.stats_btn)
    
    def update_ip_statistics(self, packet_info):
        """Update request count and metadata for an IP address."""
        src_ip = packet_info.get('src')
        if not src_ip or src_ip == 'Unknown':
            return
            
        now = time.time()
        
        if src_ip not in self.ip_stats:
            self.ip_stats[src_ip] = {
                'count': 0,
                'name': packet_info.get('src_name') or packet_info.get('src_device') or '',
                'last_seen': now,
                'history': []
            }
            
        stats = self.ip_stats[src_ip]
        stats['count'] += 1
        stats['last_seen'] = now
        stats['history'].append(now)
        
        # Keep only last 60 seconds of history for charting
        # This prevents the list from growing indefinitely
        stats['history'] = [t for t in stats['history'] if now - t <= 60]
        
        # Update name if it was empty but now available
        if not stats['name']:
            stats['name'] = packet_info.get('src_name') or packet_info.get('src_device') or ''

    def block_ip(self, ip):
        """Add IP to blocked list."""
        self.blocked_ips.add(ip)

    def unblock_ip(self, ip):
        """Remove IP from blocked list."""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)

    def show_ip_statistics(self):
        """Show the enhanced IP statistics and blocking dialog."""
        dialog = StatisticsDialog(
            self.ip_stats, 
            self.blocked_ips, 
            self.block_ip, 
            self.unblock_ip, 
            self
        )
        dialog.exec_()



    def setup_filter_bar(self):
        """Setup the filter input in the toolbar."""
        # Create filter input
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter: tcp, udp, ip.src==x.x.x.x, port==80...")
        self.filter_input.setMinimumWidth(300)
        self.filter_input.setFont(QFont("Consolas", 9))
        self.filter_input.setStyleSheet("""
            QLineEdit {
                padding: 4px 8px;
                border: 1px solid #ccc;
                border-radius: 4px;
                background: white;
            }
            QLineEdit:focus {
                border-color: #0078d4;
            }
        """)
        self.filter_input.textChanged.connect(self.on_filter_changed)
        self.filter_input.returnPressed.connect(self.apply_filter)
        
        # Add to toolbar layout
        self.ui.horizontalLayout.addWidget(QLabel("Filter:"))
        self.ui.horizontalLayout.addWidget(self.filter_input)
    
    def setup_packet_limit_dropdown(self):
        """Setup the packet limit dropdown in the toolbar."""
        self.packet_limit_combo = QComboBox()
        self.packet_limit_combo.setMinimumWidth(100)
        self.packet_limit_combo.setStyleSheet("""
            QComboBox {
                padding: 4px 8px;
                border: 1px solid #ccc;
                border-radius: 4px;
                background: white;
            }
        """)
        
        # Add options
        for label in self.PACKET_LIMIT_OPTIONS.keys():
            self.packet_limit_combo.addItem(label)
        
        self.packet_limit_combo.currentTextChanged.connect(self.on_packet_limit_changed)
        
        # Add to toolbar
        self.ui.horizontalLayout.addWidget(QLabel("  Limit:"))
        self.ui.horizontalLayout.addWidget(self.packet_limit_combo)
    
    def on_packet_limit_changed(self, text):
        """Handle packet limit dropdown change."""
        value = self.PACKET_LIMIT_OPTIONS.get(text, 0)
        
        if value == -1:  # Custom
            limit, ok = QInputDialog.getInt(
                self, 'Custom Packet Limit',
                'Enter maximum number of packets:',
                value=50000, min=1000, max=1000000, step=1000
            )
            if ok:
                self.packet_limit = limit
                # Update combo box text to show custom value
                self.packet_limit_combo.setItemText(
                    self.packet_limit_combo.currentIndex(),
                    f'Custom ({limit:,})'
                )
            else:
                # Reset to Unlimited if cancelled
                self.packet_limit_combo.setCurrentIndex(0)
                self.packet_limit = 0
        else:
            self.packet_limit = value
        
        # Apply limit immediately if we have more packets than allowed
        if self.packet_limit > 0 and len(self.raw_packets) > self.packet_limit:
            self._enforce_packet_limit()

    def on_filter_changed(self, text):
        """Handle filter text change with debounce for smoother typing."""
        self._pending_filter_text = text
        # Debounce: wait 300ms after last keystroke before applying filter
        self.filter_debounce_timer.start(300)
    
    def _apply_debounced_filter(self):
        """Apply the pending filter after debounce delay."""
        self.filter_model.set_filter(self._pending_filter_text)

    def apply_filter(self):
        """Apply the current filter immediately (on Enter key)."""
        # Cancel debounce timer and apply immediately
        self.filter_debounce_timer.stop()
        self.filter_model.set_filter(self.filter_input.text())

    def show_interface_dialog(self):
        """Show the interface selection dialog."""
        interface = InterfaceDialog.get_interface(self)
        if interface:
            self.selected_interface = interface
            self.sniffer.set_interface(interface)
            self.setWindowTitle(f"PcapQt - {interface}")
        else:
            self.setWindowTitle("PcapQt - All Interfaces")

    def show_context_menu(self, position):
        """Show context menu for packet table."""
        index = self.ui.packageTableView.indexAt(position)
        if not index.isValid():
            return
        
        # Map proxy index to source index
        source_index = self.filter_model.mapToSource(index)
        row = source_index.row()
        
        if row >= len(self.raw_packets):
            return
        
        packet = self.raw_packets[row]
        
        menu = QMenu(self)
        
        # Follow stream options
        if TCP in packet and IP in packet:
            follow_tcp = QAction("Follow TCP Stream", self)
            follow_tcp.triggered.connect(lambda: self.follow_stream(row, "TCP"))
            menu.addAction(follow_tcp)
        
        if UDP in packet and IP in packet:
            follow_udp = QAction("Follow UDP Stream", self)
            follow_udp.triggered.connect(lambda: self.follow_stream(row, "UDP"))
            menu.addAction(follow_udp)
        
        if menu.actions():
            menu.addSeparator()
        
        # Copy options
        copy_action = QAction("Copy Packet Info", self)
        copy_action.triggered.connect(lambda: self.copy_packet_info(row))
        menu.addAction(copy_action)
        
        menu.exec_(self.ui.packageTableView.viewport().mapToGlobal(position))

    def follow_stream(self, row, protocol):
        """Open stream dialog for the selected packet."""
        if row >= len(self.raw_packets):
            return
        
        packet = self.raw_packets[row]
        stream_key = StreamAnalyzer.get_stream_key_for_packet(packet)
        
        if not stream_key:
            QMessageBox.warning(self, "Error", "Cannot identify stream for this packet.")
            return
        
        # Get all packets in this stream
        stream_packets = StreamAnalyzer.filter_stream_packets(self.raw_packets, stream_key)
        
        if not stream_packets:
            QMessageBox.information(self, "Info", "No data found in this stream.")
            return
        
        # Show stream dialog
        dialog = StreamDialog(stream_packets, stream_key, self)
        dialog.exec_()

    def copy_packet_info(self, row):
        """Copy packet info to clipboard."""
        if row >= len(self.raw_packets):
            return
        
        from PyQt5.QtWidgets import QApplication
        packet_data = self.packet_model.packets[row]
        info = "\t".join(str(item) for item in packet_data)
        QApplication.clipboard().setText(info)

    def on_scroll_changed(self, value):
        """Handle scroll changes - stop autoscroll when user scrolls up."""
        scrollbar = self.ui.packageTableView.verticalScrollBar()
        
        # Detect scroll direction
        if value < self.last_scroll_value:
            # Scrolling UP - immediately stop autoscroll
            self.auto_scroll_enabled = False
        elif scrollbar.maximum() - value <= 5:
            # At bottom - re-enable autoscroll
            self.auto_scroll_enabled = True
        
        self.last_scroll_value = value

    def check_if_at_bottom(self):
        """Periodically check if scrolled to bottom to re-enable autoscroll."""
        scrollbar = self.ui.packageTableView.verticalScrollBar()
        
        if scrollbar.maximum() - scrollbar.value() <= 5:
            if not self.auto_scroll_enabled and len(self.raw_packets) > 0:
                self.auto_scroll_enabled = True
                self.last_scroll_value = scrollbar.value()
    
    def on_packet_clicked(self, index):
        """Handle click on packet - stop autoscroll and show details."""
        if not index.isValid():
            return
        
        # Stop autoscroll when user clicks
        self.auto_scroll_enabled = False
        
        # Show detail panel if not already visible
        if not self.ui.detailButton.isChecked():
            self.ui.detailButton.setChecked(True)
        
        # Display details for clicked packet
        source_index = self.filter_model.mapToSource(index)
        row = source_index.row()
        if row < len(self.raw_packets):
            self.current_packet_index = row
            packet = self.raw_packets[row]
            self.display_packet_details(packet)

    def on_capture_error(self, error_message):
        """Handle capture errors from sniffer thread."""
        # Stop capture button
        self.ui.startCapture.setChecked(False)
        # Show error message
        QMessageBox.warning(self, "Capture Error", error_message)

    def toggle_capture(self, checked):
        if checked:
            self.sniffer.start()
        else:
            self.sniffer.stop()

    def restart_capture(self):
        if self.sniffer.isRunning():
            self.sniffer.stop()
            self.sniffer.wait()

        self.packet_model.clear()
        self.detail_model.clear()
        self.raw_packets.clear()
        self.current_packet_index = -1
        self.auto_scroll_enabled = True
        
        # Invalidate filter cache
        self.filter_model.invalidate_cache()

        if self.ui.startCapture.isChecked():
            self.ui.startCapture.setChecked(False)

    def on_packet_captured(self, packet_bytes, packet_info):
        """Queue packet for batched processing (thread-safe).
        
        Args:
            packet_bytes: Raw packet bytes (thread-safe copy)
            packet_info: Parsed packet information dict
        """
        try:
            # Check if source IP is blocked
            src_ip = packet_info.get('src')
            if src_ip in self.blocked_ips:
                return
                
            # Update IP statistics
            self.update_ip_statistics(packet_info)
            
            packet_data = [
                packet_info['no'],
                f"{packet_info['time']:.6f}",
                packet_info['src'],
                packet_info['dst'],
                packet_info['protocol'],
                packet_info['length'],
                packet_info['info']
            ]
            
            with QMutexLocker(self.packet_queue_mutex):
                self.packet_queue.append((packet_bytes, packet_data))
        except Exception as e:
            print(f"Error queuing packet: {e}")
            traceback.print_exc()
    
    def process_packet_queue(self):
        """Process queued packets in batches (runs on main thread)."""
        try:
            with QMutexLocker(self.packet_queue_mutex):
                if not self.packet_queue:
                    return
                # Increased batch size for better performance under high load
                packets_to_process = self.packet_queue[:200]
                self.packet_queue = self.packet_queue[200:]
            
            # Batch insert packets to model (reduces UI updates)
            packets_data = []
            raw_packets_to_add = []
            for packet_bytes, packet_data in packets_to_process:
                # Reconstruct packet from bytes on main thread (thread-safe)
                try:
                    packet = Ether(packet_bytes)
                except Exception:
                    # If Ether parsing fails, store raw bytes
                    packet = packet_bytes
                raw_packets_to_add.append(packet)
                packets_data.append(packet_data)
            
            # Add raw packets to list
            self.raw_packets.extend(raw_packets_to_add)
            
            # Add all packets at once using batch method (single UI update)
            self.packet_model.add_packets(packets_data)
            
            # Enforce packet limit if set
            if self.packet_limit > 0:
                self._enforce_packet_limit()
            
            # Auto-scroll using scrollbar (faster than scrollTo)
            if self.auto_scroll_enabled and packets_to_process:
                # Use singleShot to defer scroll to next event loop iteration
                # This allows the view to finish updating first
                QTimer.singleShot(0, self._scroll_to_bottom)
                
        except Exception as e:
            print(f"Error processing packet queue: {e}")
            traceback.print_exc()
    
    def _enforce_packet_limit(self):
        """Remove oldest packets if we exceed the limit."""
        if self.packet_limit <= 0:
            return
        
        excess = len(self.raw_packets) - self.packet_limit
        if excess > 0:
            # Remove oldest packets from raw_packets list
            self.raw_packets = self.raw_packets[excess:]
            # Remove oldest packets from model
            self.packet_model.remove_oldest_packets(excess)
            
            # Adjust current packet index if needed
            if self.current_packet_index >= 0:
                self.current_packet_index = max(0, self.current_packet_index - excess)
    
    def _scroll_to_bottom(self):
        """Helper method to scroll to bottom."""
        if self.auto_scroll_enabled:
            scrollbar = self.ui.packageTableView.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())

    def on_packet_selected(self, current, previous):
        if not current.isValid():
            return

        # Map from filter model to source model
        source_index = self.filter_model.mapToSource(current)
        row = source_index.row()
        self.current_packet_index = row
        
        if row < len(self.raw_packets) - 1:
            self.auto_scroll_enabled = False
        
        # Only update details if detail panel is already visible
        # Don't auto-show the panel
        if row < len(self.raw_packets) and self.ui.detailButton.isChecked():
            packet = self.raw_packets[row]
            self.display_packet_details(packet)

    def display_packet_details(self, packet):
        try:
            details = PacketParser.get_packet_details(packet, self.current_packet_index)
            self.detail_model.set_details(details)
            self.ui.detailedPackageTableView.resizeColumnsToContents()
        except Exception as e:
            print(f"Error displaying packet details: {e}")
            traceback.print_exc()
            self.detail_model.set_details([['Error', str(e)]])

    def go_to_previous(self):
        current_row = self.ui.packageTableView.currentIndex().row()
        if current_row > 0:
            self.auto_scroll_enabled = False
            self.ui.packageTableView.selectRow(current_row - 1)

    def go_to_next(self):
        current_row = self.ui.packageTableView.currentIndex().row()
        if current_row < self.filter_model.rowCount() - 1:
            self.auto_scroll_enabled = False
            self.ui.packageTableView.selectRow(current_row + 1)

    def go_to_first(self):
        if self.filter_model.rowCount() > 0:
            self.auto_scroll_enabled = False
            self.ui.packageTableView.selectRow(0)

    def go_to_last(self):
        row_count = self.filter_model.rowCount()
        if row_count > 0:
            self.ui.packageTableView.selectRow(row_count - 1)
            self.auto_scroll_enabled = True

    def closeEvent(self, event):
        if self.sniffer.isRunning():
            self.sniffer.stop()
            self.sniffer.wait()
        
        self.scroll_check_timer.stop()
        self.batch_timer.stop()
        
        event.accept()