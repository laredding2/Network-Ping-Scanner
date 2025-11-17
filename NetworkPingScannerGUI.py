#!/usr/bin/env python3
"""
Network Ping Scanner
Pings all addresses in any network subnet (/0 to /32) with graphical interface
"""

import subprocess
import ipaddress
import platform
import concurrent.futures
import socket
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime
from typing import List, Tuple, Dict
import threading

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Ping Scanner V4.1")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Variables
        self.scanning = False
        self.alive_hosts = []
        self.dns_results = {}
        self.current_network = ""
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface."""
        # Header Frame
        header_frame = ttk.Frame(self.root, padding="10")
        header_frame.pack(fill=tk.X)
        
        title_label = ttk.Label(
            header_frame, 
            text="Network Ping Scanner",
            font=("Arial", 16, "bold")
        )
        title_label.pack()
        
        subtitle_label = ttk.Label(
            header_frame,
            text="Scan any network from /0 to /32 subnet mask",
            font=("Arial", 9)
        )
        subtitle_label.pack()
        
        # Input Frame
        input_frame = ttk.LabelFrame(self.root, text="Network Configuration", padding="10")
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Network Address:").grid(row=0, column=0, sticky=tk.W, padx=5)
        
        self.network_entry = ttk.Entry(input_frame, width=30, font=("Arial", 10))
        self.network_entry.grid(row=0, column=1, padx=5)
        self.network_entry.insert(0, "192.168.1.0")
        
        ttk.Label(input_frame, text="(e.g., 192.168.1.0)").grid(row=0, column=2, sticky=tk.W, padx=5)
        
        ttk.Label(input_frame, text="Subnet Mask:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.subnet_var = tk.StringVar(value="24")
        subnet_spinbox = ttk.Spinbox(
            input_frame,
            from_=0,
            to=32,
            textvariable=self.subnet_var,
            width=10
        )
        subnet_spinbox.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(input_frame, text="(/0 to /32)").grid(row=1, column=2, sticky=tk.W, padx=5)
        
        ttk.Label(input_frame, text="Max Workers:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.workers_var = tk.StringVar(value="50")
        workers_spinbox = ttk.Spinbox(
            input_frame, 
            from_=1, 
            to=100, 
            textvariable=self.workers_var,
            width=10
        )
        workers_spinbox.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Control Buttons Frame
        button_frame = ttk.Frame(self.root, padding="10")
        button_frame.pack(fill=tk.X)
        
        self.scan_button = ttk.Button(
            button_frame,
            text="Start Scan",
            command=self.start_scan,
            width=15
        )
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(
            button_frame,
            text="Stop Scan",
            command=self.stop_scan,
            state=tk.DISABLED,
            width=15
        )
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.dns_button = ttk.Button(
            button_frame,
            text="DNS Lookup",
            command=self.perform_dns_lookup,
            state=tk.DISABLED,
            width=15
        )
        self.dns_button.pack(side=tk.LEFT, padx=5)
        
        self.save_button = ttk.Button(
            button_frame,
            text="Save Results",
            command=self.save_results,
            state=tk.DISABLED,
            width=15
        )
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = ttk.Button(
            button_frame,
            text="Clear Results",
            command=self.clear_results,
            width=15
        )
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Progress Frame
        progress_frame = ttk.LabelFrame(self.root, text="Scan Progress", padding="10")
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            length=300
        )
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(
            progress_frame,
            text="Ready to scan",
            font=("Arial", 9)
        )
        self.status_label.pack()
        
        # Results Frame
        results_frame = ttk.LabelFrame(self.root, text="Scan Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create text widget with scrollbar
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            width=80,
            height=20,
            font=("Courier", 9),
            wrap=tk.WORD
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure text tags for colored output
        self.results_text.tag_config("header", foreground="blue", font=("Courier", 9, "bold"))
        self.results_text.tag_config("alive", foreground="green")
        self.results_text.tag_config("info", foreground="black")
        self.results_text.tag_config("error", foreground="red")
        self.results_text.tag_config("dns", foreground="purple")
        
        # Statistics Frame
        stats_frame = ttk.Frame(self.root, padding="10")
        stats_frame.pack(fill=tk.X)
        
        self.stats_label = ttk.Label(
            stats_frame,
            text="Total Hosts Alive: 0 | Scanned: 0/0",
            font=("Arial", 10, "bold")
        )
        self.stats_label.pack()
        
    def log_message(self, message, tag="info"):
        """Add a message to the results text widget."""
        self.results_text.insert(tk.END, message + "\n", tag)
        self.results_text.see(tk.END)
        self.root.update_idletasks()
        
    def clear_results(self):
        """Clear the results display."""
        self.results_text.delete(1.0, tk.END)
        self.alive_hosts = []
        self.dns_results = {}
        self.stats_label.config(text="Total Hosts Alive: 0 | Scanned: 0/0")
        self.progress_var.set(0)
        self.status_label.config(text="Ready to scan")
        self.dns_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        
    def start_scan(self):
        """Start the network scan in a separate thread."""
        network_input = self.network_entry.get().strip()
        
        if not network_input:
            messagebox.showerror("Error", "Please enter a network address")
            return
        
        # Remove any existing subnet mask from input
        if '/' in network_input:
            network_input = network_input.split('/')[0]
        
        # Add the subnet mask from the spinbox
        subnet_mask = self.subnet_var.get()
        network_input = f"{network_input}/{subnet_mask}"
        
        # Validate the network address
        try:
            test_net = ipaddress.IPv4Network(network_input, strict=False)
            host_count = test_net.num_addresses - 2  # Exclude network and broadcast
            
            # Warn for very large networks
            if test_net.prefixlen < 16:  # More than 65,534 hosts
                response = messagebox.askyesno(
                    "Large Network Warning",
                    f"This network has {host_count:,} hosts to scan.\n"
                    f"This will take a considerable amount of time.\n\n"
                    f"Continue anyway?"
                )
                if not response:
                    return
            elif test_net.prefixlen < 20:  # More than 4,094 hosts
                response = messagebox.askyesno(
                    "Warning",
                    f"This network has {host_count:,} hosts to scan.\n"
                    f"This may take several minutes.\n\n"
                    f"Continue?"
                )
                if not response:
                    return
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid network address: {e}")
            return
        
        self.current_network = network_input
        self.scanning = True
        self.alive_hosts = []
        self.dns_results = {}
        
        # Update UI
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.dns_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        self.clear_results()
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        scan_thread.start()
        
    def stop_scan(self):
        """Stop the current scan."""
        self.scanning = False
        self.status_label.config(text="Scan stopped by user")
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
    def run_scan(self):
        """Run the network scan."""
        try:
            net = ipaddress.IPv4Network(self.current_network, strict=False)
            
            hosts = list(net.hosts())
            total_hosts = len(hosts)
            
            # Special handling for /31 and /32 networks
            if net.prefixlen == 32:
                hosts = [net.network_address]
                total_hosts = 1
            elif net.prefixlen == 31:
                hosts = [net.network_address, net.broadcast_address]
                total_hosts = 2
            
            max_workers = int(self.workers_var.get())
            
            self.log_message(f"{'='*60}", "header")
            self.log_message(f"Scanning {total_hosts} hosts in {net}", "header")
            self.log_message(f"Subnet: /{net.prefixlen} ({net.netmask})", "header")
            self.log_message(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "header")
            self.log_message(f"{'='*60}", "header")
            self.log_message("")
            
            completed = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
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
                        self.log_message(f"[✓] {ip} is ALIVE", "alive")
                    
                    # Update progress
                    progress = (completed / total_hosts) * 100
                    self.progress_var.set(progress)
                    self.status_label.config(
                        text=f"Scanning... {completed}/{total_hosts} hosts checked"
                    )
                    self.stats_label.config(
                        text=f"Total Hosts Alive: {len(self.alive_hosts)} | Scanned: {completed}/{total_hosts}"
                    )
            
            # Scan complete
            if self.scanning:
                self.log_message("")
                self.log_message(f"{'='*60}", "header")
                self.log_message("Scan Complete!", "header")
                self.log_message(f"{'='*60}", "header")
                self.log_message(f"\nTotal hosts alive: {len(self.alive_hosts)}", "info")
                
                if self.alive_hosts:
                    self.log_message("\nAlive hosts:", "info")
                    for host in sorted(self.alive_hosts, key=lambda x: ipaddress.IPv4Address(x)):
                        self.log_message(f"  • {host}", "alive")
                    
                    self.dns_button.config(state=tk.NORMAL)
                    self.save_button.config(state=tk.NORMAL)
                else:
                    self.log_message("\nNo hosts responded to ping.", "info")
                
                self.status_label.config(text=f"Scan complete - {len(self.alive_hosts)} hosts found")
            
        except ValueError as e:
            self.log_message(f"Error: Invalid network address - {e}", "error")
            messagebox.showerror("Error", f"Invalid network address: {e}")
        except Exception as e:
            self.log_message(f"Error during scan: {e}", "error")
            messagebox.showerror("Error", f"Scan error: {e}")
        finally:
            self.scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
    
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
    
    def perform_dns_lookup(self):
        """Perform DNS lookups on alive hosts."""
        if not self.alive_hosts:
            messagebox.showinfo("Info", "No alive hosts to lookup")
            return
        
        self.dns_button.config(state=tk.DISABLED)
        self.log_message("\n" + "="*60, "header")
        self.log_message("Performing DNS Lookups...", "header")
        self.log_message("="*60, "header")
        self.log_message("")
        
        dns_thread = threading.Thread(target=self.run_dns_lookup, daemon=True)
        dns_thread.start()
    
    def run_dns_lookup(self):
        """Run DNS lookups in a separate thread."""
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
                    self.log_message(f"[DNS] {ip} → {hostname}", "dns")
                
                self.status_label.config(text=f"DNS lookup: {completed}/{total}")
        
        # Display summary
        resolved = sum(1 for h in self.dns_results.values() if h != 'N/A')
        self.log_message("")
        self.log_message(f"DNS lookups complete: {resolved}/{total} resolved", "info")
        
        # Display table
        self.log_message("\n" + "="*60, "header")
        self.log_message("DNS Lookup Results", "header")
        self.log_message("="*60, "header")
        self.log_message(f"\n{'IP Address':<20} {'Hostname'}", "info")
        self.log_message("-"*60, "info")
        
        sorted_hosts = sorted(self.alive_hosts, key=lambda x: ipaddress.IPv4Address(x))
        for host in sorted_hosts:
            hostname = self.dns_results.get(host, "N/A")
            self.log_message(f"{host:<20} {hostname}", "dns")
        
        self.status_label.config(text=f"DNS lookup complete - {resolved} hosts resolved")
        self.dns_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.NORMAL)
    
    def lookup_dns(self, ip: str) -> Tuple[str, str]:
        """Perform reverse DNS lookup for an IP address."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return (ip, hostname)
        except:
            return (ip, "N/A")
    
    def save_results(self):
        """Save scan results to a file."""
        if not self.alive_hosts:
            messagebox.showinfo("Info", "No results to save")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        network_safe = self.current_network.replace("/", "_")
        default_filename = f"scan_{network_safe}_{timestamp}.txt"
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=default_filename,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
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
            
            messagebox.showinfo("Success", f"Results saved to:\n{filename}")
            self.log_message(f"\n[✓] Results saved to: {filename}", "alive")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save results:\n{e}")
            self.log_message(f"\n[✗] Error saving results: {e}", "error")

def main():
    """Main function to run the GUI application."""
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
