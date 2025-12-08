# -*- coding: utf-8 -*-

from PyQt5.QtWidgets import (
    QMainWindow, QLineEdit, QLabel, QMenu, QAction, QMessageBox
)
from PyQt5.QtCore import QTimer, Qt, QMutex, QMutexLocker
from PyQt5.QtGui import QFont
from scapy.all import TCP, UDP, IP, Ether
import traceback

from ..ui_pcapqt import Ui_PcapQt
from ..models.packet_table_model import PacketTableModel
from ..models.packet_detail_model import PacketDetailModel
from ..models.packet_filter_model import PacketFilterModel
from ..threads.sniffer_thread import SnifferThread
from ..utils.packet_parser import PacketParser
from ..utils.stream_analyzer import StreamAnalyzer
from .interface_dialog import InterfaceDialog
from .stream_dialog import StreamDialog


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
        
        # Packet queue for batched processing
        self.packet_queue = []
        self.packet_queue_mutex = QMutex()
        
        # Batch update timer (reduces UI updates)
        self.batch_timer = QTimer()
        self.batch_timer.timeout.connect(self.process_packet_queue)
        self.batch_timer.start(50)  # Process queue every 50ms

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

        # Setup filter bar
        self.setup_filter_bar()

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

    def on_filter_changed(self, text):
        """Handle filter text change - apply filter in real-time."""
        self.filter_model.set_filter(text)

    def apply_filter(self):
        """Apply the current filter."""
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

        if self.ui.startCapture.isChecked():
            self.ui.startCapture.setChecked(False)

    def on_packet_captured(self, packet_bytes, packet_info):
        """Queue packet for batched processing (thread-safe).
        
        Args:
            packet_bytes: Raw packet bytes (thread-safe copy)
            packet_info: Parsed packet information dict
        """
        try:
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
            for packet_bytes, packet_data in packets_to_process:
                # Reconstruct packet from bytes on main thread (thread-safe)
                try:
                    packet = Ether(packet_bytes)
                except Exception:
                    # If Ether parsing fails, store raw bytes
                    packet = packet_bytes
                self.raw_packets.append(packet)
                packets_data.append(packet_data)
            
            # Add all packets at once if possible
            for packet_data in packets_data:
                self.packet_model.add_packet(packet_data)
            
            # Auto-scroll using scrollbar (faster than scrollTo)
            if self.auto_scroll_enabled and packets_to_process:
                # Use singleShot to defer scroll to next event loop iteration
                # This allows the view to finish updating first
                QTimer.singleShot(0, self._scroll_to_bottom)
                
        except Exception as e:
            print(f"Error processing packet queue: {e}")
            traceback.print_exc()
    
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