import socket
import threading
import hashlib
import re
import customtkinter as ctk
from tkinter import filedialog, messagebox
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# Global Configuration
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class CyberToolkit(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Reconnaissance Toolkit")
        self.geometry("1400x850")
        self.minsize(1100, 700)

        # Operational State Matrix
        self.last_scan_data = {}
        self.scan_is_active = False
        self.scan_history_log = [] 
        self.open_ports_list = []      # Keeps track of open ports found during the last scan
        self.ui_row_references = {}    # Stores references to UI rows to update them live

        # Structural Partitioning (Sidebar / Main Workspace)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.build_sidebar()
        self.build_main_container()

        # Direct initialization into core functionality
        self.select_view("recon")

    # ---------------- UI LAYOUT & NAVIGATION ----------------

    def build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color="#1a1a1e")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(8, weight=1)

        brand = ctk.CTkLabel(
            self.sidebar, 
            text="RECON TOOLKIT", 
            font=("Consolas", 16, "bold"), 
            text_color="#3498db"
        )
        brand.pack(pady=(25, 20), padx=20, anchor="w")

        self.nav_buttons = {}
        modules = [
            ("recon", "Network Recon Tools"),
            ("integrity", "Crypto & Integrity Tools"),
            ("dns", "DNS Lookup"),
            ("history", "Scan History")
        ]

        for view_id, label in modules:
            btn = ctk.CTkButton(
                self.sidebar,
                text=label,
                font=("Arial", 12, "bold"),
                height=38,
                anchor="w",
                fg_color="transparent",
                text_color="#a6a6a6",
                hover_color="#25252b",
                command=lambda v=view_id: self.select_view(v)
            )
            btn.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[view_id] = btn

        lbl_credits = ctk.CTkLabel(self.sidebar, text="Engine: v1.2.0\nAuth: @wakaa", font=("Consolas", 10), text_color="gray", justify="left")
        lbl_credits.pack(side="bottom", pady=15, padx=20, anchor="w")

    def build_main_container(self):
        self.container = ctk.CTkFrame(self, fg_color="#0f0f12", corner_radius=0)
        self.container.grid(row=0, column=1, sticky="nsew")
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(0, weight=1)

        self.views = {}
        view_builders = [
            ("recon", self.build_recon_view),
            ("integrity", self.build_integrity_view),
            ("dns", self.build_dns_view),
            ("history", self.build_history_view)
        ]

        for view_id, builder in view_builders:
            frame = ctk.CTkFrame(self.container, fg_color="transparent")
            self.views[view_id] = frame
            builder(frame)

    def select_view(self, target_view):
        if target_view == "history":
            self.populate_history_matrix()

        for view_id, frame in self.views.items():
            if view_id == target_view:
                frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
                self.nav_buttons[view_id].configure(fg_color="#2a2a32", text_color="white")
            else:
                frame.grid_forget()
                self.nav_buttons[view_id].configure(fg_color="transparent", text_color="#a6a6a6")

    def make_header(self, parent, title, subtitle):
        header_frame = ctk.CTkFrame(parent, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 15))
        ctk.CTkLabel(header_frame, text=title, font=("Arial", 20, "bold")).pack(anchor="w")
        ctk.CTkLabel(header_frame, text=subtitle, font=("Arial", 12), text_color="gray").pack(anchor="w", pady=2)
        ctk.CTkFrame(parent, height=1, fg_color="#25252b").pack(fill="x", pady=(0, 15))

    # ---------------- 1. CONSOLIDATED NETWORK RECON TOOLS ----------------

    def build_recon_view(self, frame):
        self.make_header(frame, "Network Recon Tools", "Port scanner with automated banner grabbing and service detection modules.")

        # Shared Global Input Bar
        cfg_bar = ctk.CTkFrame(frame, fg_color="#1a1a1e", height=55)
        cfg_bar.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(cfg_bar, text="Host:", font=("Arial", 12)).pack(side="left", padx=(15, 5))
        self.host_entry = ctk.CTkEntry(cfg_bar, width=180, placeholder_text="e.g. 192.168.1.1")
        self.host_entry.pack(side="left", padx=5, pady=10)

        ctk.CTkLabel(cfg_bar, text="Ports:", font=("Arial", 12)).pack(side="left", padx=(15, 5))
        self.start_port = ctk.CTkEntry(cfg_bar, width=50)
        self.start_port.pack(side="left", padx=2, pady=10)
        self.start_port.insert(0, "1")
        
        ctk.CTkLabel(cfg_bar, text="-", font=("Arial", 12)).pack(side="left", padx=1)
        self.end_port = ctk.CTkEntry(cfg_bar, width=50)
        self.end_port.pack(side="left", padx=2, pady=10)
        self.end_port.insert(0, "100")

        ctk.CTkLabel(cfg_bar, text="Threads:", font=("Arial", 12)).pack(side="left", padx=(15, 5))
        self.thread_entry = ctk.CTkEntry(cfg_bar, width=45)
        self.thread_entry.pack(side="left", padx=5, pady=10)
        self.thread_entry.insert(0, "40")

        # Action Buttons
        self.scan_btn = ctk.CTkButton(cfg_bar, text="Scan Ports", font=("Arial", 11, "bold"), fg_color="#3498db", hover_color="#2980b9", width=90, command=self.start_scan)
        self.scan_btn.pack(side="left", padx=(15, 4), pady=10)

        self.grab_btn = ctk.CTkButton(cfg_bar, text="Grab Banner", font=("Arial", 11, "bold"), fg_color="#2c2c35", hover_color="#3e3e4a", width=95, state="disabled", command=self.start_bulk_banner_grab)
        self.grab_btn.pack(side="left", padx=4, pady=10)

        self.detect_btn = ctk.CTkButton(cfg_bar, text="Detect Service", font=("Arial", 11, "bold"), fg_color="#2c2c35", hover_color="#3e3e4a", width=105, state="disabled", command=self.start_bulk_service_detection)
        self.detect_btn.pack(side="left", padx=4, pady=10)

        self.export_btn = ctk.CTkButton(cfg_bar, text="Export Scan", font=("Arial", 11), fg_color="#222226", hover_color="#2c2c35", state="disabled", width=85, command=self.export_scan_report)
        self.export_btn.pack(side="left", padx=(10, 5), pady=10)

        # Progress / Meta Strip
        status_strip = ctk.CTkFrame(frame, fg_color="transparent")
        status_strip.pack(fill="x", pady=(0, 5))
        self.lbl_recon_status = ctk.CTkLabel(status_strip, text="Status: IDLE", font=("Consolas", 11), text_color="gray")
        self.lbl_recon_status.pack(side="left", padx=2)
        self.lbl_recon_progress = ctk.CTkLabel(status_strip, text="Progress: 0%", font=("Consolas", 11), text_color="gray")
        self.lbl_recon_progress.pack(side="right", padx=2)

        self.progress = ctk.CTkProgressBar(frame, height=4, fg_color="#1a1a1e", progress_color="#3498db")
        self.progress.pack(fill="x", pady=(0, 10))
        self.progress.set(0)

        # Workspace split (Left: Metadata Panel, Right: Results Table)
        split_layout = ctk.CTkFrame(frame, fg_color="transparent")
        split_layout.pack(fill="both", expand=True)
        split_layout.grid_columnconfigure(0, weight=1) 
        split_layout.grid_columnconfigure(1, weight=4) 
        split_layout.grid_rowconfigure(0, weight=1)

        # Host Details Metadata Panel
        self.summary_panel = ctk.CTkFrame(split_layout, fg_color="#1a1a1e", border_width=1, border_color="#25252b")
        self.summary_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.reset_summary_card_view()

        # Port Scan Table Panel
        self.table_frame = ctk.CTkFrame(split_layout, fg_color="transparent")
        self.table_frame.grid(row=0, column=1, sticky="nsew")
        
        table_header = ctk.CTkFrame(self.table_frame, fg_color="#1a1a1e", height=28)
        table_header.pack(fill="x", pady=(0, 2))
        ctk.CTkLabel(table_header, text="PORT", font=("Consolas", 11, "bold"), width=70, anchor="w").pack(side="left", padx=15)
        ctk.CTkLabel(table_header, text="STATE", font=("Consolas", 11, "bold"), width=80, anchor="w").pack(side="left", padx=5)
        ctk.CTkLabel(table_header, text="SERVICE", font=("Consolas", 11, "bold"), width=110, anchor="w").pack(side="left", padx=5)
        ctk.CTkLabel(table_header, text="BANNER / EXTRA DATA LOG", font=("Consolas", 11, "bold"), anchor="w").pack(side="left", padx=5, fill="x", expand=True)

        self.results_table_body = ctk.CTkScrollableFrame(self.table_frame, fg_color="#111114", corner_radius=0)
        self.results_table_body.pack(fill="both", expand=True)

    # ---------------- PORT SCAN ENGINE (CLEAN) ----------------

    def start_scan(self):
        raw_target = self.host_entry.get().strip()
        if not raw_target:
            messagebox.showwarning("Input Error", "Please specify a target host address before scanning.")
            return

        self.scan_btn.configure(state="disabled")
        self.grab_btn.configure(state="disabled")
        self.detect_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.lbl_recon_status.configure(text="Status: SCANNING", text_color="#e74c3c")
        
        self.clear_ui_table()
        self.clear_summary_card_values()
        
        self.open_ports_list = []
        self.ui_row_references = {}
        self.scan_is_active = True
        
        threading.Thread(target=self.scan_ports_threaded, daemon=True).start()

    def scan_ports_threaded(self):
        raw_target = self.host_entry.get().strip()
        current_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
        
        try: 
            resolved_ip = socket.gethostbyname(raw_target)
        except Exception:
            self.lbl_recon_status.configure(text="Status: DNS ERROR", text_color="#e74c3c")
            self.scan_btn.configure(state="normal")
            self.scan_history_log.append({
                "datetime": current_timestamp,
                "target": raw_target,
                "ip": "0.0.0.0",
                "status": "Failed (DNS)"
            })
            return

        try:
            start = int(self.start_port.get())
            end = int(self.end_port.get())
            max_threads = int(self.thread_entry.get())
        except ValueError:
            self.lbl_recon_status.configure(text="Status: ENTRY ERROR", text_color="#e74c3c")
            self.scan_btn.configure(state="normal")
            return

        ports = list(range(start, end + 1))
        total_ports = len(ports)
        if total_ports <= 0: return

        start_time = datetime.now()
        self.last_scan_data = {"target": raw_target, "ip": resolved_ip, "open_ports_detailed": []}
        
        completed_count = 0
        open_count = 0
        pipeline_lock = threading.Lock()

        def check_port_worker(port):
            nonlocal completed_count, open_count
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.8)
            
            result = sock.connect_ex((resolved_ip, port))
            sock.close()

            try: 
                service_name = socket.getservbyport(port, "tcp").upper()
            except Exception: 
                service_name = "UNKNOWN"

            with pipeline_lock:
                completed_count += 1
                if result == 0:
                    open_count += 1
                    self.open_ports_list.append((port, service_name))
                    
                    row_ref = self.add_table_row(port, "OPEN", service_name, "Ready for interrogation...")
                    self.ui_row_references[port] = row_ref
                    
                    self.last_scan_data["open_ports_detailed"].append({
                        "port": port, "service": service_name, "banner": ""
                    })

                self.update_progress(completed_count, total_ports)

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            executor.map(check_port_worker, ports)

        duration = f"{(datetime.now() - start_time).total_seconds():.2f} sec"
        self.last_scan_data["duration"] = duration
        self.last_scan_data["os_fingerprint"] = "Run Banner Grabber to parse OS"

        self.print_populated_summary_card(raw_target, open_count, "Pending interrogation", duration)
        self.lbl_recon_status.configure(text="Status: FINISHED", text_color="#2ecc71")
        
        self.scan_btn.configure(state="normal")
        self.export_btn.configure(state="normal")
        if open_count > 0:
            self.grab_btn.configure(state="normal")
            self.detect_btn.configure(state="normal")

        self.scan_history_log.append({
            "datetime": current_timestamp,
            "target": raw_target,
            "ip": resolved_ip,
            "status": "Completed"
        })

    # ---------------- ON-DEMAND AUTOMATED BANNER GRAB ENGINE ----------------

    def start_bulk_banner_grab(self):
        if not self.open_ports_list: return
        self.grab_btn.configure(state="disabled")
        self.lbl_recon_status.configure(text="Status: GRABBING BANNERS", text_color="#e67e22")
        threading.Thread(target=self.bulk_banner_grab_threaded, daemon=True).start()

    def bulk_banner_grab_threaded(self):
        resolved_ip = self.last_scan_data.get("ip")
        max_threads = int(self.thread_entry.get())
        collected_banners = []
        pipeline_lock = threading.Lock()

        def grab_worker(item):
            port, service = item
            banner_info = self.fetch_raw_banner_payload(resolved_ip, port)
            
            with pipeline_lock:
                collected_banners.append(banner_info)
                if port in self.ui_row_references:
                    self.ui_row_references[port]["banner"].configure(text=str(banner_info), text_color="#d1d1d1")
                
                for data_item in self.last_scan_data["open_ports_detailed"]:
                    if data_item["port"] == port:
                        data_item["banner"] = banner_info

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            executor.map(grab_worker, self.open_ports_list)

        detected_os = self.fingerprint_target_os(collected_banners)
        self.last_scan_data["os_fingerprint"] = detected_os
        
        self.print_populated_summary_card(
            self.last_scan_data["target"], 
            len(self.open_ports_list), 
            detected_os, 
            self.last_scan_data["duration"]
        )
        
        self.lbl_recon_status.configure(text="Status: BANNERS COMPLETE", text_color="#2ecc71")
        self.grab_btn.configure(state="normal")

    def fetch_raw_banner_payload(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(1.5)
            s.connect((ip, port))
            
            if port in [80, 443, 8080]:
                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode('utf-8'))
            else:
                s.sendall(b"\r\n")
                
            payload = s.recv(1024)
            s.close()
            
            if payload:
                decoded = payload.decode('utf-8', errors='replace').replace('\n', ' ').replace('\r', '').strip()
                cleaned = re.sub(r'\s+', ' ', decoded)
                return cleaned[:75] + "..." if len(cleaned) > 75 else cleaned
            return "Active Server Connection (No clear banner text payload)"
        except Exception: 
            return "Response Timeout / Dropped Packets"

    # ---------------- ON-DEMAND SERVICE ANALYSIS INTERROGATION ----------------

    def start_bulk_service_detection(self):
        if not self.open_ports_list: return
        self.detect_btn.configure(state="disabled")
        self.lbl_recon_status.configure(text="Status: INTERROGATING SERVICES", text_color="#9b59b6")
        threading.Thread(target=self.bulk_service_detection_threaded, daemon=True).start()

    def bulk_service_detection_threaded(self):
        resolved_ip = self.last_scan_data.get("ip")
        max_threads = int(self.thread_entry.get())
        pipeline_lock = threading.Lock()

        def analyze_worker(item):
            port, service_name = item
            detected_signature = service_name
            
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.settimeout(2.0)
                s.connect((resolved_ip, port))
                
                if port in [80, 443, 8080]:
                    req = f"GET / HTTP/1.1\r\nHost: {resolved_ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                    s.sendall(req.encode('utf-8'))
                    res = s.recv(1024).decode('utf-8', errors='replace')
                    for line in res.split("\n"):
                        if line.lower().startswith("server:"):
                            detected_signature = line.split(":", 1)[1].strip().upper()
                            break
                else:
                    s.sendall(b"HELP\r\n")
                    res = s.recv(512).decode('utf-8', errors='replace').strip()
                    if res:
                        cleaned = re.sub(r'[^a-zA-h0-9\-\/\s]', '', res).replace('\n', ' ')
                        detected_signature = cleaned[:20].strip().upper()
                s.close()
            except Exception:
                pass

            with pipeline_lock:
                if port in self.ui_row_references:
                    self.ui_row_references[port]["service"].configure(text=str(detected_signature), text_color="#e74c3c")
                    self.ui_row_references[port]["banner"].configure(text="Service profiling analysis finalized.", text_color="#7f8c8d")
                
                for data_item in self.last_scan_data["open_ports_detailed"]:
                    if data_item["port"] == port:
                        data_item["service"] = detected_signature

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            executor.map(analyze_worker, self.open_ports_list)

        self.lbl_recon_status.configure(text="Status: SERVICES DEPLOYED", text_color="#2ecc71")
        self.detect_btn.configure(state="normal")

    # ---------------- RECON PLATFORM INTERFACE UTILITIES ----------------

    def clear_ui_table(self):
        for widget in self.results_table_body.winfo_children(): widget.destroy()

    def add_table_row(self, port, status, service, banner):
        row = ctk.CTkFrame(self.results_table_body, fg_color="#16161a", height=28, corner_radius=0)
        row.pack(fill="x", pady=1, padx=1)
        
        lbl_p = ctk.CTkLabel(row, text=str(port), font=("Consolas", 12), width=70, anchor="w", text_color="#a6a6a6")
        lbl_p.pack(side="left", padx=15)
        
        lbl_s = ctk.CTkLabel(row, text=status, font=("Consolas", 11, "bold"), width=80, anchor="w", text_color="#2ecc71")
        lbl_s.pack(side="left", padx=5)
        
        lbl_srv = ctk.CTkLabel(row, text=service, font=("Consolas", 12), width=110, anchor="w", text_color="#3498db" if service != "UNKNOWN" else "gray")
        lbl_srv.pack(side="left", padx=5)
        
        lbl_ban = ctk.CTkLabel(row, text=banner, font=("Consolas", 11), anchor="w", text_color="#555555")
        lbl_ban.pack(side="left", padx=5, fill="x", expand=True)
        
        return {"row": row, "status": lbl_s, "service": lbl_srv, "banner": lbl_ban}

    def update_progress(self, current, total):
        self.progress.set(current / total)
        self.lbl_recon_progress.configure(text=f"Progress: {current/total*100:.1f}% ({current}/{total})")

    def reset_summary_card_view(self):
        for w in self.summary_panel.winfo_children(): 
            w.destroy()
            
        ctk.CTkLabel(self.summary_panel, text="Host Details", font=("Arial", 13, "bold"), text_color="#3498db").pack(anchor="w", pady=(15, 12), padx=15)
        
        self.summary_metrics = {}
        metrics_list = ["Target", "State", "Open Ports", "OS Guess", "Duration"]
        
        for field in metrics_list:
            m_frame = ctk.CTkFrame(self.summary_panel, fg_color="transparent", height=28)
            m_frame.pack(fill="x", padx=15, pady=3)
            m_frame.pack_propagate(False) 
            
            ctk.CTkLabel(m_frame, text=f"{field}:", font=("Arial", 11, "bold"), text_color="gray").pack(side="left")
            
            val_lbl = ctk.CTkLabel(m_frame, text="-", font=("Consolas", 11), text_color="white", anchor="w")
            val_lbl.pack(side="right", fill="x")
            
            self.summary_metrics[field] = val_lbl

    def clear_summary_card_values(self):
        if hasattr(self, 'summary_metrics'):
            for field in self.summary_metrics:
                self.summary_metrics[field].configure(text="-")

    def print_populated_summary_card(self, target, open_ports, os_guess, duration):
        if hasattr(self, 'summary_metrics'):
            self.summary_metrics["Target"].configure(text=str(target))
            self.summary_metrics["State"].configure(text="Completed")
            self.summary_metrics["Open Ports"].configure(text=str(open_ports))
            self.summary_metrics["OS Guess"].configure(text=str(os_guess))
            self.summary_metrics["Duration"].configure(text=str(duration))

    def fingerprint_target_os(self, collected_banners):
        combined = " ".join(collected_banners).lower()
        if re.search(r"ubuntu|debian|centos|redhat|fedora|linux", combined): return "Linux OS"
        if re.search(r"microsoft-iis|windows|win32|win64", combined): return "Windows Server"
        return "Generic Core Stack"

    def export_scan_report(self):
        if not self.last_scan_data: return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Log", "*.txt")])
        if not file_path: return
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(f"RECON SCAN REPORT\n{'='*40}\n")
                f.write(f"Target: {self.last_scan_data['target']} ({self.last_scan_data['ip']})\n")
                f.write(f"OS Guess: {self.last_scan_data.get('os_fingerprint', 'Unknown')}\n\n")
                for item in self.last_scan_data.get("open_ports_detailed", []):
                    f.write(f"Port: {item['port']} | Service: {item['service']} | Banner: {item['banner']}\n")
            messagebox.showinfo("Success", "Report written cleanly to storage asset.")
        except Exception as e: messagebox.showerror("Error", str(e))

    # ---------------- 2. CONSOLIDATED CRYPTO & INTEGRITY TOOLS ----------------

    def build_integrity_view(self, frame):
        self.make_header(frame, "Crypto & Integrity Tools", "Combined cryptographic validation pane for standalone hashes and file comparisons.")

        workspace = ctk.CTkFrame(frame, fg_color="transparent")
        workspace.pack(fill="both", expand=True)
        workspace.grid_columnconfigure(0, weight=1)
        workspace.grid_columnconfigure(1, weight=1)
        workspace.grid_rowconfigure(0, weight=1)

        hash_pane = ctk.CTkFrame(workspace, fg_color="#1a1a1e", border_width=1, border_color="#25252b")
        hash_pane.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        ctk.CTkLabel(hash_pane, text="Hash Generator", font=("Arial", 14, "bold"), text_color="#3498db").pack(anchor="w", padx=15, pady=15)
        ctk.CTkButton(hash_pane, text="Select Target File", font=("Arial", 12), fg_color="#2c2c35", hover_color="#3e3e4a", command=self.generate_hash).pack(fill="x", padx=15, pady=5)
        
        self.hash_box = ctk.CTkTextbox(hash_pane, font=("Consolas", 11), fg_color="#111114")
        self.hash_box.pack(fill="both", expand=True, padx=15, pady=15)

        compare_pane = ctk.CTkFrame(workspace, fg_color="#1a1a1e", border_width=1, border_color="#25252b")
        compare_pane.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        ctk.CTkLabel(compare_pane, text="File Integrity Check", font=("Arial", 14, "bold"), text_color="#3498db").pack(anchor="w", padx=15, pady=15)
        
        self.file1, self.file2 = None, None
        self.btn_f1 = ctk.CTkButton(compare_pane, text="Load Primary Object (File 1)", fg_color="#2c2c35", hover_color="#3e3e4a", command=self.pick_file1)
        self.btn_f1.pack(fill="x", padx=15, pady=5)

        self.btn_f2 = ctk.CTkButton(compare_pane, text="Load Secondary Object (File 2)", fg_color="#2c2c35", hover_color="#3e3e4a", command=self.pick_file2)
        self.btn_f2.pack(fill="x", padx=15, pady=5)

        ctk.CTkButton(compare_pane, text="Compare Signatures", font=("Arial", 12, "bold"), fg_color="#3498db", hover_color="#2980b9", command=self.compare_files).pack(fill="x", padx=15, pady=15)
        
        self.file_result = ctk.CTkLabel(compare_pane, text="Awaiting targets...", font=("Consolas", 12), text_color="gray", wraplength=350)
        self.file_result.pack(fill="x", padx=15, pady=5)

    def generate_hash(self):
        path = filedialog.askopenfilename()
        if not path: return
        try:
            sha = hashlib.sha256()
            with open(path, "rb") as file:
                while chunk := file.read(4096): sha.update(chunk)
            self.hash_box.delete("1.0", "end")
            self.hash_box.insert("1.0", f"Context File Object:\n{path}\n\nSHA-256 Digest Matrix Signature:\n{sha.hexdigest()}")
        except Exception as e: self.hash_box.insert("end", f"Execution Fault: {str(e)}")

    def pick_file1(self):
        self.file1 = filedialog.askopenfilename()
        if self.file1: self.btn_f1.configure(text="✓ Primary File Object Set", fg_color="#232329")

    def pick_file2(self):
        self.file2 = filedialog.askopenfilename()
        if self.file2: self.btn_f2.configure(text="✓ Secondary File Object Set", fg_color="#232329")

    def compare_files(self):
        if not self.file1 or not self.file2:
            self.file_result.configure(text="Evaluation Failed: Both paths must be loaded.", text_color="#e74c3c")
            return
        def compute(p):
            s = hashlib.sha256()
            with open(p, "rb") as f:
                while c := f.read(4096): s.update(c)
            return s.hexdigest()
        if compute(self.file1) == compute(self.file2):
            self.file_result.configure(text="MATCH: File signatures are completely identical.", text_color="#2ecc71")
        else:
            self.file_result.configure(text="MISMATCH: Structural differences identified.", text_color="#e74c3c")

    # ---------------- 3. DNS LOOKUP VIEW ----------------

    def build_dns_view(self, frame):
        self.make_header(frame, "DNS Lookup", "Resolves destination domain strings into explicit routing addresses.")

        control_frame = ctk.CTkFrame(frame, fg_color="#1a1a1e")
        control_frame.pack(fill="x", pady=5)

        self.dns_entry = ctk.CTkEntry(control_frame, placeholder_text="Target URL Address (e.g., https://example.com)", width=320)
        self.dns_entry.pack(side="left", padx=15, pady=12)

        dns_btn = ctk.CTkButton(control_frame, text="Resolve DNS", font=("Arial", 12, "bold"), command=self.start_dns_conversion)
        dns_btn.pack(side="left", padx=15, pady=12)

        self.dns_box = ctk.CTkTextbox(frame, font=("Consolas", 12), fg_color="#111114")
        self.dns_box.pack(fill="both", expand=True, pady=15)

    def start_dns_conversion(self):
        raw_url = self.dns_entry.get().strip()
        self.dns_box.delete("1.0", "end")
        if not raw_url:
            messagebox.showwarning("Input Error", "Please provide a valid URL string.")
            return
        
        def run():
            parsed = urlparse(raw_url)
            domain = parsed.netloc if parsed.netloc else parsed.path
            domain = domain.split('/')[0].split(':')[0]
            self.dns_box.insert("end", f"[*] Parsing domain node trace: {domain}\n")
            try:
                ip_list = socket.gethostbyname_ex(domain)[2]
                out = f"[+] Host Resolution Process Complete:\n\nDomain Pointer : {domain}\nPrimary Target Node: {ip_list[0]}\n"
                if len(ip_list) > 1:
                    out += "\nAssociated Infrastructure Matrix Pool:\n"
                    for idx, ip in enumerate(ip_list, 1): out += f"   └── [{idx}] {ip}\n"
                self.dns_box.insert("end", out)
            except Exception as e: self.dns_box.insert("end", f"[-] Dynamic resolution failure context: {str(e)}")
        threading.Thread(target=run, daemon=True).start()

    # ---------------- 4. SCAN HISTORY VIEW ----------------

    def build_history_view(self, frame):
        self.make_header(frame, "Scan History", "Persistent session matrix logging active target evaluations.")

        matrix_container = ctk.CTkFrame(frame, fg_color="transparent")
        matrix_container.pack(fill="both", expand=True)

        matrix_header = ctk.CTkFrame(matrix_container, fg_color="#1a1a1e", height=30)
        matrix_header.pack(fill="x", pady=(0, 2))
        
        ctk.CTkLabel(matrix_header, text="DATE & TIME", font=("Consolas", 11, "bold"), width=160, anchor="w").pack(side="left", padx=15)
        ctk.CTkLabel(matrix_header, text="TARGET HOST", font=("Consolas", 11, "bold"), width=240, anchor="w").pack(side="left", padx=5)
        ctk.CTkLabel(matrix_header, text="RESOLVED IP", font=("Consolas", 11, "bold"), width=180, anchor="w").pack(side="left", padx=5)
        ctk.CTkLabel(matrix_header, text="STATUS", font=("Consolas", 11, "bold"), anchor="w").pack(side="left", padx=5, fill="x", expand=True)

        self.history_table_body = ctk.CTkScrollableFrame(matrix_container, fg_color="#111114", corner_radius=0)
        self.history_table_body.pack(fill="both", expand=True)

    def populate_history_matrix(self):
        for widget in self.history_table_body.winfo_children():
            widget.destroy()

        if not self.scan_history_log:
            empty_row = ctk.CTkFrame(self.history_table_body, fg_color="transparent", height=40)
            empty_row.pack(fill="x", pady=20)
            ctk.CTkLabel(empty_row, text="No tracking history logs captured within this session.", font=("Arial", 12), text_color="gray").pack()
            return

        for index, log in enumerate(reversed(self.scan_history_log)):
            row = ctk.CTkFrame(self.history_table_body, fg_color="#16161a", height=30, corner_radius=0)
            row.pack(fill="x", pady=1, padx=1)
            
            status_txt = log["status"]
            status_color = "#2ecc71" if "Completed" in status_txt else "#e74c3c"

            ctk.CTkLabel(row, text=log["datetime"], font=("Consolas", 12), width=160, anchor="w", text_color="#a6a6a6").pack(side="left", padx=15)
            ctk.CTkLabel(row, text=log["target"], font=("Consolas", 12), width=240, anchor="w", text_color="white").pack(side="left", padx=5)
            ctk.CTkLabel(row, text=log["ip"], font=("Consolas", 12), width=180, anchor="w", text_color="#3498db").pack(side="left", padx=5)
            ctk.CTkLabel(row, text=status_txt, font=("Consolas", 11, "bold"), anchor="w", text_color=status_color).pack(side="left", padx=5, fill="x", expand=True)


if __name__ == "__main__":
    app = CyberToolkit()
    app.mainloop()
