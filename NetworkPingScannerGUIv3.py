#!/usr/bin/env python3
"""
Network Ping Scanner - PyQt5 Version
Pings all addresses in any network subnet (/0 to /32) with graphical interface
"""

import subprocess
import ipaddress
import platform
import concurrent.futures
import socket
import sys
from datetime import datetime
from typing import List, Tuple, Dict
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QSpinBox, QPushButton, QTextEdit, QProgressBar,
    QGroupBox, QFileDialog, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QTextCursor, QColor


class ScanThread(QThread):
    """Thread for running the network scan."""
    progress_update = pyqtSignal(int, int, int)  # completed, total, alive_count
    log_message = pyqtSignal(str, str)  # message, tag
    scan_complete = pyqtSignal(list)  # alive_hosts
    
    def __init__(self, network, max_workers):
        super().__init__()
        self.network = network
        self.max_workers = max_workers
        self.scanning = True
        self.alive_hosts = []
    
    def run(self):
        """Run the network scan."""
        try:
            net = ipaddress.ip_network(self.network, strict=False)
            hosts = list(net.hosts()) if net.num_addresses > 2 else [net.network_address]
            total_hosts = len(hosts)
            
            self.log_message.emit(f"{'='*60}", "header")
            self.log_message.emit(f"Scanning Network: {self.network}", "header")
            self.log_message.emit(f"Total hosts to scan: {total_hosts:,}", "header")
            self.log_message.emit(f"Network range: {net.network_address} - {net.broadcast_address}", "header")
            self.log_message.emit(f"Subnet: /{net.prefixlen} ({net.netmask})", "header")
            self.log_message.emit(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "header")
            self.log_message.emit(f"{'='*60}", "header")
            self.log_message.emit("", "info")
            
            completed = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_ip = {
                    executor.submit(self.ping_host, str(ip)): ip 
                    for ip in hosts
                }
                
                for future in concurrent.futures.as_completed(future_to_ip):
                    if not self.scanning:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    
                    ip, is_alive = future.result()
                    completed += 1
                    
                    if is_alive:
                        self.alive_hosts.append(ip)
                        self.log_message.emit(f"[✓] {ip} is ALIVE", "alive")
                    
                    # Update progress
                    self.progress_update.emit(completed, total_hosts, len(self.alive_hosts))
            
            # Scan complete
            if self.scanning:
                self.log_message.emit("", "info")
                self.log_message.emit(f"{'='*60}", "header")
                self.log_message.emit("Scan Complete!", "header")
                self.log_message.emit(f"{'='*60}", "header")
                self.log_message.emit(f"\nTotal hosts alive: {len(self.alive_hosts)}", "info")
                
                if self.alive_hosts:
                    self.log_message.emit("\nAlive hosts:", "info")
                    for host in sorted(self.alive_hosts, key=lambda x: ipaddress.IPv4Address(x)):
                        self.log_message.emit(f"  • {host}", "alive")
                else:
                    self.log_message.emit("\nNo hosts responded to ping.", "info")
                
                self.scan_complete.emit(self.alive_hosts)
                
        except ValueError as e:
            self.log_message.emit(f"Error: Invalid network address - {e}", "error")
        except Exception as e:
            self.log_message.emit(f"Error during scan: {e}", "error")
    
    def ping_host(self, ip: str, timeout: int = 1) -> Tuple[str, bool]:
        """Ping a single host and return the result."""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        
        command = ['ping', param, '1', timeout_param, str(timeout), ip]
        
        try:
            output = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout + 1
            )
            return (ip, output.returncode == 0)
        except:
            return (ip, False)
    
    def stop(self):
        """Stop the scan."""
        self.scanning = False


class DNSThread(QThread):
    """Thread for running DNS lookups."""
    log_message = pyqtSignal(str, str)  # message, tag
    progress_update = pyqtSignal(int, int)  # completed, total
    dns_complete = pyqtSignal(dict)  # dns_results
    
    def __init__(self, alive_hosts):
        super().__init__()
        self.alive_hosts = alive_hosts
        self.dns_results = {}
    
    def run(self):
        """Run DNS lookups."""
        self.log_message.emit("\n" + "="*60, "header")
        self.log_message.emit("Performing DNS Lookups...", "header")
        self.log_message.emit("="*60, "header")
        self.log_message.emit("", "info")
        
        total = len(self.alive_hosts)
        completed = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_ip = {
                executor.submit(self.lookup_dns, ip): ip 
                for ip in self.alive_hosts
            }
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip, hostname = future.result()
                self.dns_results[ip] = hostname
                completed += 1
                
                if hostname != "N/A":
                    self.log_message.emit(f"[DNS] {ip} → {hostname}", "dns")
                
                self.progress_update.emit(completed, total)
        
        # Display summary
        resolved = sum(1 for h in self.dns_results.values() if h != 'N/A')
        self.log_message.emit("", "info")
        self.log_message.emit(f"DNS lookups complete: {resolved}/{total} resolved", "info")
        
        # Display table
        self.log_message.emit("\n" + "="*60, "header")
        self.log_message.emit("DNS Lookup Results", "header")
        self.log_message.emit("="*60, "header")
        self.log_message.emit(f"\n{'IP Address':<20} {'Hostname'}", "info")
        self.log_message.emit("-"*60, "info")
        
        sorted_hosts = sorted(self.alive_hosts, key=lambda x: ipaddress.IPv4Address(x))
        for host in sorted_hosts:
            hostname = self.dns_results.get(host, "N/A")
            self.log_message.emit(f"{host:<20} {hostname}", "dns")
        
        self.dns_complete.emit(self.dns_results)
    
    def lookup_dns(self, ip: str) -> Tuple[str, str]:
        """Perform reverse DNS lookup for an IP address."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return (ip, hostname)
        except:
            return (ip, "N/A")


class NetworkScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Ping Scanner V3 - PyQt5")
        self.setGeometry(100, 100, 900, 700)
        
        # Variables
        self.scanning = False
        self.alive_hosts = []
        self.dns_results = {}
        self.current_network = ""
        self.scan_thread = None
        self.dns_thread = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface."""
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        
        # Header
        header_layout = QVBoxLayout()
        title_label = QLabel("Network Ping Scanner")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(title_label)
        
        subtitle_label = QLabel("Scan any network from /0 to /32 subnet mask")
        subtitle_label.setFont(QFont("Arial", 9))
        subtitle_label.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(subtitle_label)
        main_layout.addLayout(header_layout)
        
        # Input Group
        input_group = QGroupBox("Network Configuration")
        input_layout = QVBoxLayout()
        
        # Network Address
        network_layout = QHBoxLayout()
        network_layout.addWidget(QLabel("Network Address:"))
        self.network_entry = QLineEdit("192.168.1.0")
        self.network_entry.setFont(QFont("Arial", 10))
        network_layout.addWidget(self.network_entry)
        network_layout.addWidget(QLabel("(e.g., 192.168.1.0)"))
        input_layout.addLayout(network_layout)
        
        # Subnet Mask
        subnet_layout = QHBoxLayout()
        subnet_layout.addWidget(QLabel("Subnet Mask:"))
        self.subnet_spinbox = QSpinBox()
        self.subnet_spinbox.setRange(0, 32)
        self.subnet_spinbox.setValue(24)
        subnet_layout.addWidget(self.subnet_spinbox)
        subnet_layout.addWidget(QLabel("(/0 to /32)"))
        subnet_layout.addStretch()
        input_layout.addLayout(subnet_layout)
        
        # Max Workers
        workers_layout = QHBoxLayout()
        workers_layout.addWidget(QLabel("Max Workers:"))
        self.workers_spinbox = QSpinBox()
        self.workers_spinbox.setRange(1, 100)
        self.workers_spinbox.setValue(50)
        workers_layout.addWidget(self.workers_spinbox)
        workers_layout.addStretch()
        input_layout.addLayout(workers_layout)
        
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)
        
        # Control Buttons
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        self.dns_button = QPushButton("DNS Lookup")
        self.dns_button.clicked.connect(self.perform_dns_lookup)
        self.dns_button.setEnabled(False)
        button_layout.addWidget(self.dns_button)
        
        self.save_button = QPushButton("Save Results")
        self.save_button.clicked.connect(self.save_results)
        self.save_button.setEnabled(False)
        button_layout.addWidget(self.save_button)
        
        self.clear_button = QPushButton("Clear Results")
        self.clear_button.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_button)
        
        main_layout.addLayout(button_layout)
        
        # Progress Group
        progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to scan")
        self.status_label.setFont(QFont("Arial", 9))
        self.status_label.setAlignment(Qt.AlignCenter)
        progress_layout.addWidget(self.status_label)
        
        progress_group.setLayout(progress_layout)
        main_layout.addWidget(progress_group)
        
        # Results Group
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setFont(QFont("Courier", 9))
        results_layout.addWidget(self.results_text)
        
        results_group.setLayout(results_layout)
        main_layout.addWidget(results_group)
        
        # Statistics
        self.stats_label = QLabel("Total Hosts Alive: 0 | Scanned: 0/0")
        self.stats_label.setFont(QFont("Arial", 10, QFont.Bold))
        self.stats_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.stats_label)
    
    def log_message(self, message, tag="info"):
        """Add a message to the results text widget with color formatting."""
        cursor = self.results_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        # Set color based on tag
        color_map = {
            "header": QColor(0, 0, 255),      # Blue
            "alive": QColor(0, 128, 0),       # Green
            "info": QColor(0, 0, 0),          # Black
            "error": QColor(255, 0, 0),       # Red
            "dns": QColor(128, 0, 128)        # Purple
        }
        
        color = color_map.get(tag, QColor(0, 0, 0))
        format = cursor.charFormat()
        format.setForeground(color)
        
        if tag == "header":
            font = QFont("Courier", 9, QFont.Bold)
            format.setFont(font)
        else:
            font = QFont("Courier", 9)
            format.setFont(font)
        
        cursor.setCharFormat(format)
        cursor.insertText(message + "\n")
        
        self.results_text.setTextCursor(cursor)
        self.results_text.ensureCursorVisible()
    
    def clear_results(self):
        """Clear the results display."""
        self.results_text.clear()
        self.alive_hosts = []
        self.dns_results = {}
        self.stats_label.setText("Total Hosts Alive: 0 | Scanned: 0/0")
        self.progress_bar.setValue(0)
        self.status_label.setText("Ready to scan")
        self.dns_button.setEnabled(False)
        self.save_button.setEnabled(False)
    
    def start_scan(self):
        """Start the network scan in a separate thread."""
        network_addr = self.network_entry.text().strip()
        subnet = self.subnet_spinbox.value()
        
        if not network_addr:
            QMessageBox.warning(self, "Warning", "Please enter a network address")
            return
        
        try:
            self.current_network = f"{network_addr}/{subnet}"
            ipaddress.ip_network(self.current_network, strict=False)
        except ValueError as e:
            QMessageBox.critical(self, "Error", f"Invalid network address: {e}")
            return
        
        # Clear previous results
        self.results_text.clear()
        self.alive_hosts = []
        self.dns_results = {}
        self.progress_bar.setValue(0)
        
        # Update UI state
        self.scanning = True
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.dns_button.setEnabled(False)
        self.save_button.setEnabled(False)
        self.status_label.setText("Starting scan...")
        
        # Start scan thread
        max_workers = self.workers_spinbox.value()
        self.scan_thread = ScanThread(self.current_network, max_workers)
        self.scan_thread.progress_update.connect(self.update_progress)
        self.scan_thread.log_message.connect(self.log_message)
        self.scan_thread.scan_complete.connect(self.scan_finished)
        self.scan_thread.start()
    
    def stop_scan(self):
        """Stop the current scan."""
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.status_label.setText("Stopping scan...")
            self.log_message("\nScan stopped by user", "error")
        
        self.scanning = False
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
    
    def update_progress(self, completed, total, alive_count):
        """Update the progress bar and statistics."""
        progress = int((completed / total) * 100)
        self.progress_bar.setValue(progress)
        self.status_label.setText(f"Scanning... {completed}/{total} hosts checked")
        self.stats_label.setText(f"Total Hosts Alive: {alive_count} | Scanned: {completed}/{total}")
    
    def scan_finished(self, alive_hosts):
        """Handle scan completion."""
        self.alive_hosts = alive_hosts
        self.scanning = False
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        if self.alive_hosts:
            self.dns_button.setEnabled(True)
            self.save_button.setEnabled(True)
        
        self.status_label.setText(f"Scan complete - {len(self.alive_hosts)} hosts found")
    
    def perform_dns_lookup(self):
        """Perform DNS lookups on alive hosts."""
        if not self.alive_hosts:
            QMessageBox.information(self, "Info", "No alive hosts to lookup")
            return
        
        self.dns_button.setEnabled(False)
        
        # Start DNS thread
        self.dns_thread = DNSThread(self.alive_hosts)
        self.dns_thread.log_message.connect(self.log_message)
        self.dns_thread.progress_update.connect(self.update_dns_progress)
        self.dns_thread.dns_complete.connect(self.dns_finished)
        self.dns_thread.start()
    
    def update_dns_progress(self, completed, total):
        """Update DNS lookup progress."""
        self.status_label.setText(f"DNS lookup: {completed}/{total}")
    
    def dns_finished(self, dns_results):
        """Handle DNS lookup completion."""
        self.dns_results = dns_results
        resolved = sum(1 for h in self.dns_results.values() if h != 'N/A')
        self.status_label.setText(f"DNS lookup complete - {resolved} hosts resolved")
        self.dns_button.setEnabled(True)
        self.save_button.setEnabled(True)
    
    def save_results(self):
        """Save scan results to a file."""
        if not self.alive_hosts:
            QMessageBox.information(self, "Info", "No results to save")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        network_safe = self.current_network.replace("/", "_")
        default_filename = f"scan_{network_safe}_{timestamp}.txt"
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Results",
            default_filename,
            "Text files (*.txt);;All files (*.*)"
        )
        
        if not filename:
            return
        
        try:
            with open(filename, 'w') as f:
                f.write("=" * 60 + "\n")
                f.write("Network Scan Results\n")
                f.write("=" * 60 + "\n")
                f.write(f"Network: {self.current_network}\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Hosts Alive: {len(self.alive_hosts)}\n")
                f.write("=" * 60 + "\n\n")
                
                f.write("Alive Hosts:\n")
                f.write("-" * 60 + "\n")
                
                sorted_hosts = sorted(self.alive_hosts, key=lambda x: ipaddress.IPv4Address(x))
                
                if self.dns_results:
                    f.write(f"{'IP Address':<20} {'Hostname'}\n")
                    f.write("-" * 60 + "\n")
                    for host in sorted_hosts:
                        hostname = self.dns_results.get(host, "N/A")
                        f.write(f"{host:<20} {hostname}\n")
                else:
                    for host in sorted_hosts:
                        f.write(f"  • {host}\n")
                
                f.write("\n" + "=" * 60 + "\n")
                f.write("End of Report\n")
                f.write("=" * 60 + "\n")
            
            QMessageBox.information(self, "Success", f"Results saved to:\n{filename}")
            self.log_message(f"\n[✓] Results saved to: {filename}", "alive")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save results:\n{e}")
            self.log_message(f"\n[✗] Error saving results: {e}", "error")


def main():
    """Main function to run the GUI application."""
    app = QApplication(sys.argv)
    window = NetworkScannerGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
