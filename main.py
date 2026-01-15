import customtkinter as ctk
import threading
import time
from zapv2 import ZAPv2
import os
import glob
import json
import tkinter.messagebox
from datetime import datetime
import webbrowser
import webbrowser
import math
import requests
import db_manager
import shutil
import subprocess
import time
from tkinter import filedialog # Import filedialog for file picker


# --- PATH FIX: Ensure we run relative to the script location ---
try:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(base_dir)
    print(f"📂 Directorio de trabajo establecido en: {base_dir}")
except Exception as e:
    print(f"⚠️ No se pudo cambiar el directorio de trabajo: {e}")

# Constants
ZAP_API_KEY = "12345"
ZAP_PROXY_IP = "127.0.0.1"
ZAP_PROXY_PORT = 8080 # Default, but can change dynamicall
ZAP_PROXY_PORT = 8080
ZAP_API_KEY = ''

# Directories
DIR_RAW = "zap_answer"
DIR_SPLIT = "zap_answer_split"
DIR_FINAL = "final_json"

class VulnerabilityScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Google Material Colors
        self.COLOR_PRIMARY = "#1A73E8"    # Google Blue
        self.COLOR_HOVER = "#1557B0"      # Darker Blue
        self.COLOR_BG = "#F8F9FA"         # Light Gray Background
        self.COLOR_CARD = "#FFFFFF"       # White Card
        self.COLOR_TEXT = "#202124"       # Google Dark Gray Text
        self.COLOR_TEXT_LIGHT = "#5F6368" # Google Light Gray Text
        self.COLOR_BORDER = "#DADCE0"     # Light Border

        self.title("ScanApp - Vulnerability Scanner")
        self.geometry("900x950")
        self.configure(fg_color=self.COLOR_BG) # Set main background
        self.grid_columnconfigure(0, weight=1)
        
        self.is_scanning = False
        self.stop_requested = False
        self.last_report_file = None 
        
        # --- Header ---
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        
        self.header_label = ctk.CTkLabel(self.header_frame, text="🛡️ Search Console Scanner", font=("Roboto Medium", 28), text_color=self.COLOR_TEXT)
        self.header_label.pack(side="left")
        
        # --- Section 1: Scanner Config (Card) ---
        self.scan_card = ctk.CTkFrame(self, fg_color=self.COLOR_CARD, corner_radius=12, border_width=1, border_color=self.COLOR_BORDER)
        self.scan_card.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.scan_card.grid_columnconfigure(1, weight=1) # Expand Entry
        
        # Title
        ctk.CTkLabel(self.scan_card, text="🎯 Configuración del Objetivo", font=("Roboto Medium", 16), text_color=self.COLOR_PRIMARY).grid(row=0, column=0, columnspan=3, sticky="w", padx=20, pady=(15, 10))

        # URL Input
        self.url_entry = ctk.CTkEntry(self.scan_card, placeholder_text="Ingresa la URL del sitio web (ej: https://example.com)", height=40, font=("Roboto", 14), border_color=self.COLOR_BORDER)
        self.url_entry.grid(row=1, column=0, columnspan=2, padx=20, pady=5, sticky="ew")
        
        self.browser_var = ctk.StringVar(value="Firefox Headless")
        self.browser_option = ctk.CTkOptionMenu(
            self.scan_card, 
            values=["Firefox Headless", "Firefox", "Chrome Headless"],
            variable=self.browser_var,
            fg_color="white", text_color=self.COLOR_TEXT, button_color=self.COLOR_BORDER, button_hover_color="#E8EAED",
            dropdown_fg_color="white", dropdown_text_color=self.COLOR_TEXT
        )
        self.browser_option.grid(row=1, column=2, padx=20, pady=5)

        # Advanced options expander (simulated with just more rows)
        ctk.CTkLabel(self.scan_card, text="Archivos Fuente:", font=("Roboto", 12, "bold"), text_color=self.COLOR_TEXT).grid(row=2, column=0, padx=20, pady=(15,0), sticky="w")
        
        # Routes
        self.routes_entry = ctk.CTkEntry(self.scan_card, placeholder_text="Rutas (web.php)...", width=200, border_color=self.COLOR_BORDER)
        self.routes_entry.grid(row=3, column=0, padx=(20, 5), pady=5, sticky="ew")
        ctk.CTkButton(self.scan_card, text="Examinar", width=80, command=self.browse_routes_file, fg_color=self.COLOR_BG, text_color=self.COLOR_PRIMARY, hover_color="#E8F0FE").grid(row=3, column=1, padx=5, sticky="w")

        # Source
        self.source_entry = ctk.CTkEntry(self.scan_card, placeholder_text="Código Fuente (Carpeta)...", width=200, border_color=self.COLOR_BORDER)
        self.source_entry.grid(row=4, column=0, padx=(20, 5), pady=5, sticky="ew")
        ctk.CTkButton(self.scan_card, text="Examinar", width=80, command=self.browse_source_folder, fg_color=self.COLOR_BG, text_color=self.COLOR_PRIMARY, hover_color="#E8F0FE").grid(row=4, column=1, padx=5, sticky="w")
        
        # Swagger
        self.swagger_entry = ctk.CTkEntry(self.scan_card, placeholder_text="Swagger (swagger.json)...", width=200, border_color=self.COLOR_BORDER)
        self.swagger_entry.grid(row=5, column=0, padx=(20, 5), pady=5, sticky="ew")
        ctk.CTkButton(self.scan_card, text="Examinar", width=80, command=self.browse_swagger_file, fg_color=self.COLOR_BG, text_color=self.COLOR_PRIMARY, hover_color="#E8F0FE").grid(row=5, column=1, padx=5, sticky="w")

        # Auth
        ctk.CTkLabel(self.scan_card, text="Autenticación:", font=("Roboto", 12, "bold"), text_color=self.COLOR_TEXT).grid(row=2, column=2, padx=20, pady=(15,0), sticky="w")
        self.auth_user = ctk.CTkEntry(self.scan_card, placeholder_text="Usuario", width=140, border_color=self.COLOR_BORDER)
        self.auth_user.grid(row=3, column=2, padx=20, pady=5, sticky="w")
        self.auth_pass = ctk.CTkEntry(self.scan_card, placeholder_text="Contraseña", show="*", width=140, border_color=self.COLOR_BORDER)
        self.auth_pass.grid(row=4, column=2, padx=20, pady=5, sticky="w")
        
        # Padding bottom
        ctk.CTkLabel(self.scan_card, text="").grid(row=6, column=0, pady=5)


        # --- Section 2: AI Config (Card) ---
        self.ai_card = ctk.CTkFrame(self, fg_color=self.COLOR_CARD, corner_radius=12, border_width=1, border_color=self.COLOR_BORDER)
        self.ai_card.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        self.ai_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.ai_card, text="🧠 Inteligencia Artificial", font=("Roboto Medium", 16), text_color="#A142F4").grid(row=0, column=0, columnspan=3, sticky="w", padx=20, pady=(15, 10))

        # API Key
        self.api_key_entry = ctk.CTkEntry(self.ai_card, placeholder_text="Gemini API Key...", show="*", border_color=self.COLOR_BORDER)
        self.api_key_entry.grid(row=1, column=0, columnspan=2, padx=20, pady=5, sticky="ew")
        
        ctk.CTkButton(self.ai_card, text="Obtener Key", width=100, command=self.open_apikey_url, fg_color=self.COLOR_BG, text_color=self.COLOR_PRIMARY, hover_color="#E8F0FE").grid(row=1, column=2, padx=20)

        # Tech Stack
        self.tech_stack_entry = ctk.CTkEntry(self.ai_card, placeholder_text="Stack Tecnológico (ej: Laravel, React)...", border_color=self.COLOR_BORDER)
        self.tech_stack_entry.grid(row=2, column=0, columnspan=2, padx=20, pady=5, sticky="ew")
        
        self.detect_btn = ctk.CTkButton(self.ai_card, text="✨ Auto Detectar", width=120, command=self.detect_stack, fg_color="#E8F0FE", text_color=self.COLOR_PRIMARY, hover_color="#D2E3FC")
        self.detect_btn.grid(row=2, column=2, padx=20)

        # Toggles
        self.is_local_var = ctk.BooleanVar(value=True)
        self.local_check = ctk.CTkCheckBox(self.ai_card, text="Entorno Local (Localhost)", variable=self.is_local_var, text_color=self.COLOR_TEXT, checkbox_height=20, checkbox_width=20, corner_radius=50)
        self.local_check.grid(row=3, column=0, padx=20, pady=10, sticky="w")

        self.deep_scan_var = ctk.BooleanVar(value=False)
        self.deep_scan_check = ctk.CTkCheckBox(self.ai_card, text="Escaneo Profundo (Lento)", variable=self.deep_scan_var, text_color=self.COLOR_TEXT, checkbox_height=20, checkbox_width=20, corner_radius=50)
        self.deep_scan_check.grid(row=3, column=1, padx=20, pady=10, sticky="w")
        
        # --- Controls ---
        self.btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.btn_frame.grid(row=3, column=0, padx=20, pady=15)

        self.scan_button = ctk.CTkButton(self.btn_frame, text="ANALIZAR AHORA", command=self.start_full_process, fg_color=self.COLOR_PRIMARY, hover_color=self.COLOR_HOVER, width=200, height=45, corner_radius=22, font=("Roboto Medium", 14))
        self.scan_button.pack(side="left", padx=10)

        self.analyze_btn = ctk.CTkButton(self.btn_frame, text="Solo IA", command=self.start_analysis_only, fg_color="#F1F3F4", text_color=self.COLOR_TEXT, hover_color="#E8EAED", width=120, height=45, corner_radius=22)
        self.analyze_btn.pack(side="left", padx=10)
        
        self.report_button = ctk.CTkButton(self.btn_frame, text="Ver Reporte", command=self.open_dashboard, fg_color="#34A853", hover_color="#2D9249", width=140, height=45, corner_radius=22, state="disabled")
        self.report_button.pack(side="left", padx=10)

        self.cancel_button = ctk.CTkButton(self.btn_frame, text="Cancelar", command=self.cancel_scan, fg_color="transparent", text_color="#EA4335", hover_color="#FCE8E6", width=100, height=45, state="disabled")
        self.cancel_button.pack(side="left", padx=10)

        self.shutdown_button = ctk.CTkButton(self.btn_frame, text="Apagar ZAP", command=self.shutdown_zap, fg_color="#EA4335", hover_color="#C62828", width=120, height=45, corner_radius=22, state="disabled")
        self.shutdown_button.pack(side="left", padx=10)

        # --- Progress Log (Card) ---
        self.log_card = ctk.CTkFrame(self, fg_color=self.COLOR_CARD, corner_radius=12, border_width=1, border_color=self.COLOR_BORDER)
        self.log_card.grid(row=4, column=0, padx=20, pady=10, sticky="nsew")
        self.grid_rowconfigure(4, weight=1) # Log expands
        
        self.status_label = ctk.CTkLabel(self.log_card, text="Estado: Esperando...", text_color=self.COLOR_TEXT_LIGHT, font=("Roboto", 12))
        self.status_label.pack(anchor="w", padx=15, pady=(10,0))

        self.log_textbox = ctk.CTkTextbox(self.log_card, height=150, fg_color="#F1F3F4", text_color=self.COLOR_TEXT, corner_radius=8)
        self.log_textbox.pack(fill="both", expand=True, padx=15, pady=10)
        self.log_textbox.configure(state="disabled")

        # Progress Bars (Thin Google Style)
        self.scan_progress_bar = ctk.CTkProgressBar(self.log_card, height=4, progress_color=self.COLOR_PRIMARY)
        self.scan_progress_bar.pack(fill="x", padx=0, pady=0)
        self.scan_progress_bar.set(0)
        
        self.ai_progress_bar = ctk.CTkProgressBar(self.log_card, height=4, progress_color="#A142F4") # Purple for AI
        self.ai_progress_bar.pack(fill="x", padx=0, pady=(2,0))
        self.ai_progress_bar.set(0)

        # Initialize ZAP in a separate thread to not block GUI
        import threading
        
        # Check for existing report to enable button
        if os.path.exists("dashboard.html"):
            self.report_button.configure(state="normal")
            
        threading.Thread(target=self.check_and_start_zap, daemon=True).start()

    def check_and_start_zap(self):
        """Checks if ZAP is running. If not, tries to start it in daemon mode."""
        time.sleep(1) # Give GUI time to render
        self.log("🔍 Verificando servicio ZAP...")
        global ZAP_PROXY_PORT
        
        if not shutil.which("java"):
            self.log("⚠️ Java no detectado en PATH global. Buscando dinámicamente instalacion de Java...")
            found_java = False
            
            # Buscar en ubicaciones estándar
            search_bases = [
                r"C:\Program Files\Java",
                r"C:\Program Files (x86)\Java"
            ]
            
            potential_paths = []
            for base in search_bases:
                if os.path.exists(base):
                    # Buscar carpetas que empiecen por jdk o jre
                    potential_paths.extend(glob.glob(os.path.join(base, "jdk*")))
                    potential_paths.extend(glob.glob(os.path.join(base, "jre*")))
            
            # Ordenar para intentar usar la versión más reciente
            potential_paths.sort(reverse=True)
            
            # Añadir ruta Oracle común por si acaso
            potential_paths.append(r"C:\Program Files\Common Files\Oracle\Java\javapath")

            for p in potential_paths:
                # Si es carpeta jdk/jre, buscar bin. 
                bin_path = os.path.join(p, "bin") if "Java" in p and ("jdk" in os.path.basename(p) or "jre" in os.path.basename(p)) else p
                
                if os.path.exists(os.path.join(bin_path, "java.exe")):
                    self.log(f"✅ Java encontrado en: {bin_path}")
                    os.environ["PATH"] += os.pathsep + bin_path
                    found_java = True
                    break
            
            if not found_java:
                self.log("❌ ERROR CRÍTICO: No se encontró ninguna instalación de Java.")

        # 0. Check for Java (Again)
        if not shutil.which("java"):
            self.log("❌ ERROR CRÍTICO: Java no detectado en el sistema.")
            self.log("ℹ️ ZAP requiere Java para ejecutarse. Por favor instale Java o agréguelo al PATH.")
            return

        # 1. Attempt to find a working ZAP or a free port
        # We check 8080, then 8090, 8091...
        ports_to_try = [8080, 8090, 8091, 8092, 8093, 8094, 8095]
        
        for port in ports_to_try:
            try:
                # Check if ZAP is already here
                url = f"http://{ZAP_PROXY_IP}:{port}/JSON/core/view/version/"
                res = requests.get(url, params={'apikey': ZAP_API_KEY}, timeout=1)
                
                if res.status_code == 200 and "version" in res.text:
                    self.log(f"✅ ZAP encontrado en puerto {port} (v{res.json().get('version', '?')}).")
                    ZAP_PROXY_PORT = port # Update global
                    
                    self.zap = ZAPv2(
                        apikey=None,
                        proxies={'http': f'http://{ZAP_PROXY_IP}:{port}', 'https': f'http://{ZAP_PROXY_IP}:{port}'}
                    )
                    
                    # Enable Shutdown Button
                    self.shutdown_button.configure(state="normal")
                    return
                else:
                    self.log(f"⚠️ Puerto {port} ocupado por otro servicio. Probando siguiente...")
            
            except requests.exceptions.ConnectionError:
                # Port is likely FREE (nothing listening). We will use this port to launch ZAP.
                self.log(f"ℹ️ Puerto {port} libre. Se usará para ZAP.")
                ZAP_PROXY_PORT = port # Set this as the target port
                break # Proceed to launch
            except Exception as e:
                 self.log(f"⚠️ Error verificando puerto {port}: {e}")

        # 2. Launch ZAP Daemon on ZAP_PROXY_PORT
        zap_paths = [
            r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat", # Found path
            r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
            r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
            os.path.expanduser(r"~\OWASP ZAP\zap.bat")
        ]
        
        path_found = None
        for p in zap_paths:
            if os.path.exists(p):
                path_found = p
                break
        
        if path_found:
            self.log(f"🚀 Iniciando ZAP (Puerto {ZAP_PROXY_PORT}) desde: {path_found}")
            try:
                # IMPORTANT: Run ZAP from its own directory so it finds the .jar
                zap_dir = os.path.dirname(path_found)
                
                # LAUNCH COMMAND with permissions
                cmd = [
                    path_found, 
                    "-daemon", 
                    "-port", str(ZAP_PROXY_PORT), 
                    "-host", "127.0.0.1",
                    "-config", "api.disablekey=true",
                    "-config", "api.addrs.addr.name=.*",
                    "-config", "api.addrs.addr.regex=true"
                ]
                
                subprocess.Popen(cmd, cwd=zap_dir, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
                
                # Wait for ZAP to initialize
                self.log("⏳ Esperando a que ZAP inicie (esto puede tardar 20-40s)...")
                
                for i in range(60):
                    time.sleep(1)
                    if i % 5 == 0: self.log(f"   ... esperando ({i}s)")
                    
                    is_ready = False
                    try:
                        r = requests.get(f"http://{ZAP_PROXY_IP}:{ZAP_PROXY_PORT}", timeout=2)
                        if r.status_code == 200:
                            is_ready = True
                    except: pass

                    if is_ready:
                        self.log(f"✅ ZAP iniciado y respondiendo en el puerto {ZAP_PROXY_PORT}!")
                        
                        # Initialize Client
                        self.zap = ZAPv2(
                            apikey=None, 
                            proxies={'http': f'http://{ZAP_PROXY_IP}:{ZAP_PROXY_PORT}', 'https': f'http://{ZAP_PROXY_IP}:{ZAP_PROXY_PORT}'}
                        )
                        
                        # Enable Shutdown Button (Thread Safe)
                        self.after(0, lambda: self.shutdown_button.configure(state="normal"))
                        
                        self.log("⏳ Esperando 5s estricto para base de datos...")
                        time.sleep(5) 
                        return
                
                self.log("❌ Timeout esperando a ZAP. Posibles causas:")
                self.log("   - Java no está instalado o configurado.")
                self.log("   - El puerto esta bloqueado.")
                self.log("   - ZAP tardó demasiado (intente de nuevo).")
            except Exception as e:
                self.log(f"❌ Error lanzando ZAP: {e}")
        else:
            self.log("❌ No se encontró 'zap.bat'. Por favor instale ZAP o inícielo manualmente.")
        

    def shutdown_zap(self):
        """Attempts to shutdown ZAP via API."""
        if not self.zap: return
        
        if tkinter.messagebox.askyesno("Confirmar", "¿Seguro que quieres apagar ZAP?\nEsto detendrá cualquier escaneo en segundo plano."):
            self.log("🛑 Intentando apagar ZAP...")
            try:
                # Check status first
                try: 
                    requests.get(f"http://{ZAP_PROXY_IP}:{ZAP_PROXY_PORT}", timeout=1)
                except:
                    self.log("⚠️ ZAP ya parece estar apagado.")
                    self.shutdown_button.configure(state="disabled")
                    return

                # Send shutdown command
                self.zap.core.shutdown()
                self.log("✅ Comando de apagado enviado.")
                
                # Wait to confirm
                time.sleep(2)
                self.shutdown_button.configure(state="disabled")
                self.log("ℹ️ ZAP debería estar cerrándose.")
            except Exception as e:
                 self.log(f"❌ Error al apagar ZAP: {e}")
        


    # --- GUI Helpers ---
    def browse_routes_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Code Files", "*.php;*.py;*.js;*.java;*.ts"), ("All Files", "*.*")])
        if filename:
            self.routes_entry.delete(0, "end")
            self.routes_entry.insert(0, filename)

    def browse_source_folder(self):
        dirname = filedialog.askdirectory()
        if dirname:
            self.source_entry.delete(0, "end")
            self.source_entry.insert(0, dirname)

    def browse_swagger_file(self):
        filename = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json"), ("YAML Files", "*.yaml;*.yml"), ("All Files", "*.*")])
        if filename:
            self.swagger_entry.delete(0, "end")
            self.swagger_entry.insert(0, filename)

    def log(self, message):
         self.after(0, lambda: self._log_impl(message))

    def _log_impl(self, message):
        self.log_textbox.configure(state="normal")
        self.log_textbox.insert("end", f"> {message}\n")
        self.log_textbox.see("end")
        self.log_textbox.configure(state="disabled")

    def update_status(self, text, color="white"):
        self.after(0, lambda: self.status_label.configure(text=text, text_color=color))

    def update_scan_progress(self, val):
        self.after(0, lambda: self.scan_progress_bar.set(val))

    def update_ai_progress(self, val):
        self.after(0, lambda: self.ai_progress_bar.set(val))

    def enable_controls(self, report_ready=False):
        self.after(0, lambda: self._enable_controls_impl(report_ready))

    def _enable_controls_impl(self, report_ready):
        self.scan_button.configure(state="normal")
        self.analyze_btn.configure(state="normal")
        self.cancel_button.configure(state="disabled", fg_color="gray")
        if report_ready:
            self.report_button.configure(state="normal")

    def disable_controls(self):
        self.scan_button.configure(state="disabled")
        self.analyze_btn.configure(state="disabled")
        self.report_button.configure(state="disabled")
        self.cancel_button.configure(state="normal", fg_color="#F39C12")

    def cancel_scan(self):
        if self.is_scanning:
            self.stop_requested = True
            self.log("⚠️ Cancelando...")

    def open_dashboard(self):
        if os.path.exists("dashboard.html"):
            webbrowser.open(os.path.abspath("dashboard.html"))
        else:
            tkinter.messagebox.showwarning("Info", "No se encuentra el archivo dashboard.html")

    def open_apikey_url(self):
        webbrowser.open("https://aistudio.google.com/app/apikey")

    def detect_stack(self):
        url = self.url_entry.get()
        if not url: return
        self.log(f"🔍 Detectando tecnologías en {url}...")
        
        try:
            detected = []
            try: res = requests.get(url, verify=False, timeout=5)
            except: 
                self.log("⚠️ No se pudo conectar para detectar stack.")
                return

            # Headers
            server = res.headers.get('Server')
            powered = res.headers.get('X-Powered-By')
            if server: detected.append(server)
            if powered: detected.append(powered)
            
            # HTML
            text = res.text.lower()
            if "laravel" in text or "csrf_token" in text: detected.append("Laravel")
            if "wordpress" in text or "wp-content" in text: detected.append("WordPress")
            if "react" in text: detected.append("React")
            if "vue" in text: detected.append("Vue.js")
            if "django" in text: detected.append("Django")
            
            if detected:
                stack_str = ", ".join(list(set(detected)))
                self.tech_stack_entry.delete(0, "end")
                self.tech_stack_entry.insert(0, stack_str)
                self.log(f"✅ Stack detectado: {stack_str}")
            else:
                self.log("ℹ️ No se detectaron tecnologías obvias.")
                
        except Exception as e:
            self.log(f"⚠️ Error detectando stack: {e}")

    # --- CORE PROCESS ---
    def start_full_process(self):
        url = self.url_entry.get()
        api_key = self.api_key_entry.get()
        
        if not url:
            tkinter.messagebox.showerror("Error", "Falta la URL")
            return
        if not api_key:
            tkinter.messagebox.showwarning("Aviso", "Sin API Key de Gemini, la parte de IA fallará.")
            
        self.is_scanning = True
        self.stop_requested = False
        self.disable_controls()
        self.update_scan_progress(0)
        self.update_ai_progress(0)
        
        # Prepare directories
        self.prepare_directories()

        threading.Thread(target=self.run_process_thread, args=(url, api_key), daemon=True).start()

    # Stub to support Swagger arg update if needed in run_process_thread logic
    # Actually run_process_thread reads the entries directly from 'self' in the original code? 
    # Ah no, looking at line 284: routes_file = self.routes_entry.get(). 
    # It reads inside the thread. So passing args is not strictly necessary for fields, but cleanliness is good.
    # However, since GUI methods are not thread-safe strictly, it IS better to read them here and pass them.
    # But for minimal refactor, I will stick to reading inside or updating the thread start if I changed the signature.
    # Original signature: def run_process_thread(self, target, api_key):
    # It reads self.routes_entry.get() inside. So no signature change needed.
    pass

    def start_analysis_only(self):
        api_key = self.api_key_entry.get()
        if not api_key:
            tkinter.messagebox.showwarning("Aviso", "Necesitas la API Key para analizar.")
            return

        # Check for existing raw report
        raw_path = os.path.join(DIR_RAW, "reporte_raw.json")
        if not os.path.exists(raw_path):
            tkinter.messagebox.showerror("Error", f"No existe un escaneo previo en:\n{raw_path}")
            return

        self.is_scanning = True
        self.stop_requested = False
        self.disable_controls()
        self.update_ai_progress(0)
        
        # Don't touch scan progress, just AI
        threading.Thread(target=self.run_analysis_thread, args=(raw_path, api_key), daemon=True).start()

    def prepare_directories(self):
        # Create dirs if not exist
        for d in [DIR_RAW, DIR_SPLIT, DIR_FINAL]:
            if not os.path.exists(d):
                os.makedirs(d)
            else:
                # Clean up existing files
                for f in os.listdir(d):
                    try:
                        os.remove(os.path.join(d, f))
                    except: pass

    def run_process_thread(self, target, api_key):
        try:
            # === PHASE 0: AI ROUTE DISCOVERY & AUTH ===
            routes_file = self.routes_entry.get()
            auth_user = self.auth_user.get()
            auth_pass = self.auth_pass.get()
            
            ai_data = None
            if routes_file and os.path.exists(routes_file):
                self.update_status("Analizando rutas con IA...", "purple")
                import ai_analyzer
                ai_data = ai_analyzer.analyze_routes_and_auth(
                    routes_file, api_key, self.tech_stack_entry.get(), self.log
                )
            
            # === PHASE 1: SCANNING ===
            # === PHASE 1: SCANNING ===
            deep_scan = self.deep_scan_var.get()
            swagger_path = self.swagger_entry.get()
            
            if not self.run_zap_scan(target, ai_data, auth_user, auth_pass, deep_scan, swagger_path):
                return # Stop if failed or cancelled

            # === PHASE 2: AI ANLYSIS (WEB) ===
            web_json = None
            if self.last_report_file:
                web_json = ai_analyzer.analyze_report(
                    json_path=self.last_report_file,
                    api_key=api_key,
                    tech_stack=self.tech_stack_entry.get(),
                    is_local=self.is_local_var.get(),
                    log_func=self.log,
                    progress_func=self.update_ai_progress
                )
            
            # === PHASE 3: SAST ANALYSIS (CODE) ===
            source_dir = self.source_entry.get()
            sast_results = []
            if source_dir and os.path.exists(source_dir):
                self.update_status("Ejecutando Análisis SAST...", "purple")
                sast_results = ai_analyzer.analyze_codebase(
                    source_dir, api_key, self.tech_stack_entry.get(), self.log, self.update_ai_progress
                )
            
            # === MERGE & GENERATE FINAL REPORT ===
            # If we have both, we need to merge the JSONs and regenerate HTML
            final_data = []
            
            # Load Web Results
            if web_json and os.path.exists(web_json):
                with open(web_json, 'r', encoding='utf-8') as f:
                    final_data.extend(json.load(f))
            
            # Add SAST Results
            if sast_results:
                final_data.extend(sast_results)
                
            # Regenerate Dashboard with everything
            if final_data:
                 final_path = os.path.join(DIR_FINAL, "analisis_completo.json")
                 with open(final_path, 'w', encoding='utf-8') as f:
                     json.dump(final_data, f, indent=2)
                 
                 ai_analyzer.create_dashboard_html(final_data, "zap_answer/reporte_raw.json", "final_json/analisis_completo.json")
                 
                 # Save to DB History
                 stats = {5: 0, 4: 0, 3: 0, 2: 0, 1: 0}
                 for item in final_data:
                     s = item.get('risk_score', 0)
                     stats[s] = stats.get(s, 0) + 1
                 
                 db_manager.add_scan(target, stats, os.path.abspath("dashboard.html"))
                 self.log(f"💾 Guardado en Historial DB.")
                 
                 self.log(f"✨ ANÁLISIS COMPLETADO (Web + SAST).")

        except Exception as e:
            self.log(f"❌ ERROR GENERAL: {e}")
        finally:
            self.is_scanning = False
            self.enable_controls(report_ready=True)
            self.update_status("Listo", "white")
            self.after(0, lambda: tkinter.messagebox.showinfo("Éxito", "¡Análisis Inteligente Terminado!\nAbre el reporte HTML."))

    def run_analysis_thread(self, json_path, api_key):
        try:
            # Re-run logic similar to above but without ZAP
            import ai_analyzer
            
            # Web Analysis
            self.log("🤖 Iniciando Re-Análisis Web...")
            web_json_path = ai_analyzer.analyze_report(
                json_path=json_path,
                api_key=api_key,
                tech_stack=self.tech_stack_entry.get(),
                is_local=self.is_local_var.get(),
                log_func=self.log,
                progress_func=self.update_ai_progress
            )
            
            # SAST Analysis
            source_dir = self.source_entry.get()
            sast_results = []
            if source_dir and os.path.exists(source_dir):
                self.update_status("Ejecutando Análisis SAST...", "purple")
                sast_results = ai_analyzer.analyze_codebase(
                    source_dir, api_key, self.tech_stack_entry.get(), self.log, self.update_ai_progress
                )

            # Merge
            final_data = []
            if web_json_path and os.path.exists(web_json_path):
                 with open(web_json_path, 'r', encoding='utf-8') as f: final_data.extend(json.load(f))
            if sast_results: final_data.extend(sast_results)

            if final_data:
                 ai_analyzer.create_dashboard_html(final_data, json_path, "final_json/analisis_completo.json")

        except Exception as e:
            self.log(f"❌ ERROR ANÁLISIS: {e}")
        finally:
            self.is_scanning = False
            self.enable_controls(report_ready=True)
            self.update_status("Análisis Finalizado", "white")

    def run_zap_scan(self, target, ai_data=None, auth_user=None, auth_pass=None, deep_scan=False, swagger_path=None):
        self.log(f"--- FASE 1: ESCANEO ZAP ---")
        
        # 0. Setup Auth & Routes
        if ai_data:
            routes = ai_data.get('routes', [])
            self.log(f"🧠 IA encontró {len(routes)} rutas nuevas en el código.")
            for r in routes:
                # Construct full URL. Handle leading slash.
                full_url = target.rstrip("/") + "/" + r.lstrip("/")
                self.log(f"   -> Seed: {r}")
                # We can seed these by accessing them once or letting spider know
                # Ideally, we pass them to spider.scan(url=...) but that takes one URL.
                # A trick is to access them via a quick request or add to scope.
                try: 
                    self.zap.spider.scan(url=full_url) 
                    pass 
                except: pass

        # Swagger Logic
        if swagger_path and os.path.exists(swagger_path):
            self.log(f"📜 Cargando definición Swagger/OpenAPI: {os.path.basename(swagger_path)}")
            try:
                # 1. Try ZAP Import (Best Effort)
                # self.zap.openapi.import_file(swagger_path, target) # This might crash if addon missing
                
                # 2. Manual Parse (Robust)
                with open(swagger_path, 'r', encoding='utf-8') as f:
                    swagger_data = json.load(f)
                    
                paths = swagger_data.get('paths', {})
                self.log(f"   -> Encontrados {len(paths)} endpoints en Swagger.")
                
                for p in paths:
                    # Replace {param} with dummy
                    clean_path = p.replace("{", "").replace("}", "") # Very basic
                    full_swag_url = target.rstrip("/") + "/" + clean_path.lstrip("/")
                    try:
                        self.zap.spider.scan(url=full_swag_url)
                    except: pass
            except Exception as e:
                self.log(f"⚠️ Error procesando Swagger: {e}")

            # === SPIDER ===
            self.log("🕷️ Iniciando SPIDER (Rastreo)...")
            scan_id = self.zap.spider.scan(url=target)
            
            # Polling Loop for Spider
            time.sleep(2)
            while int(self.zap.spider.status(scan_id)) < 100:
                prog = int(self.zap.spider.status(scan_id))
                self.log(f"   🕸️ Spider Progreso: {prog}%")
                self.update_scan_progress(prog / 200.0) # 0-50%
                time.sleep(2)
            
            self.log("✅ Spider Completado.")
            # TODO: Log found URLs? self.zap.spider.results(scan_id)

            # === ACTIVE SCAN ===
            self.log("🔥 Iniciando ACTIVE SCAN (Ataque)...")
            ascan_id = self.zap.ascan.scan(url=target)
            
            # Polling Loop for Active Scan
            time.sleep(2)
            while int(self.zap.ascan.status(ascan_id)) < 100:
                prog = int(self.zap.ascan.status(ascan_id))
                # Try to get simplified log of what's happening (limited API)
                self.log(f"   🔥 Active Scan Progreso: {prog}%")
                self.update_scan_progress(0.5 + (prog / 200.0)) # 50-100%
                time.sleep(3)
                
            self.log("✅ Active Scan Completado.")
            
            # Export
        # Deep Scan: Sensitive Fuzzing Seeding
        if deep_scan:
            self.log("🕵️ Modo Profundo: Sembrando archivos sensibles (Top 50 SecLists)...")
            # Expanded List based on SecLists/Discovery/Web-Content/Raft-Medium & Common
            sensitive_paths = [
                # Config & Env
                "/.env", "/.env.local", "/.env.production", "/.env.development", 
                "/.git/config", "/.git/HEAD", "/.vscode/settings.json", "/.idea/workspace.xml",
                "/config.php.bak", "/wp-config.php.bak", "/.htaccess", "/nginx.conf",
                
                # Backups
                "/backup.sql", "/database.sql", "/dump.sql", "/backup.zip", "/site.tar.gz",
                "/backup.tar.gz", "/old.zip", "/www.zip", 
                
                # Admin & Dashboard
                "/admin", "/administrator", "/dashboard", "/panel", "/cpanel", "/login", "/wp-admin",
                "/phpmyadmin", "/adminer.php", "/telescope", "/horizon", # Laravel stuff
                
                # Cloud & CI/CD
                "/aws.yml", "/.aws/credentials", "/docker-compose.yml", "/Dockerfile", 
                "/jenkins/login", "/.gitlab-ci.yml", "/.circleci/config.yml",
                
                # Logs & Misc
                "/server-status", "/phpinfo.php", "/debug.log", "/error.log", "/access.log",
                "/sitemap.xml", "/robots.txt", "/swagger.json", "/api-docs"
            ]
            for path in sensitive_paths:
                full_fuzz = target.rstrip("/") + path
                try: self.zap.spider.scan(url=full_fuzz)
                except: pass

        # Configure Auth if Credentials + AI Auth Config logic exists
        if auth_user and auth_pass and ai_data and 'auth_config' in ai_data:
            self.configure_zap_auth(target, auth_user, auth_pass, ai_data['auth_config'])

        try:
            # 1. Spider
            scan_id = self.zap.spider.scan(target)
            
            while int(self.zap.spider.status(scan_id)) < 100:
                if self.stop_requested: return False
                # Spider 0-20%
                prog = int(self.zap.spider.status(scan_id)) / 100 * 0.2
                self.update_scan_progress(prog)
                time.sleep(1)
            
            self.update_scan_progress(0.2)
            self.log("✅ Spider completado.")

            self.log("✅ Spider completado.")

            # 2. AJAX Spider (Only if Deep Scan is ON)
            if deep_scan:
                browser = self.browser_var.get()
                # Map choice to ZAP ID
                zap_browser = "firefox-headless"
                if "Firefox" in browser and "Headless" not in browser: zap_browser = "firefox"
                elif "Chrome" in browser: zap_browser = "chrome-headless"

                self.update_status(f"Escaneando (AJAX Spider - {zap_browser})...", "cyan")
                try:
                    self.zap.ajaxSpider.set_option_browser_id(zap_browser)
                except: pass
                
                self.zap.ajaxSpider.scan(target)
                
                start_ajax = time.time()
                ajax_status = 'running'
                while ajax_status == 'running':
                    if self.stop_requested: 
                        self.zap.ajaxSpider.stop()
                        return False
                    
                    # AJAX 20-50% (Fake progress based on time, max 5 min)
                    elapsed = time.time() - start_ajax
                    prog = 0.2 + min((elapsed / 300) * 0.3, 0.3)
                    self.update_scan_progress(prog)
                    
                    if elapsed > 300: # Timeout
                        self.zap.ajaxSpider.stop()
                        break
                    
                    # Robust status check
                    try:
                        ajax_status = self.zap.ajaxSpider.status
                    except Exception as e:
                        # Ignore connection errors during heavy load
                        self.log(f"⚠️ ZAP lento respondiendo (AJAX)... esperando.")
                        time.sleep(2)
                        continue
                        
                    time.sleep(1)
                
                self.update_scan_progress(0.5)
                self.log("✅ AJAX Spider completado.")
            else:
                self.log("⏩ Saltando Ajax Spider (Modo Rápido)")
                self.update_scan_progress(0.5)

            # 3. Active Scan
            self.update_status("Escaneando (Ataque Activo)...", "orange")
            scan_id = self.zap.ascan.scan(target)
            
            while int(self.zap.ascan.status(scan_id)) < 100:
                if self.stop_requested: self.zap.ascan.stop(); return False
                
                # Active Scan 50-100%
                prog = 0.5 + (int(self.zap.ascan.status(scan_id)) / 100 * 0.5)
                self.update_scan_progress(prog)
                
                # Also update status label with %
                self.update_status(f"Ataque Activo: {self.zap.ascan.status(scan_id)}%", "orange")
                time.sleep(2)

            # Export
            self.update_scan_progress(1.0)
            alerts = self.zap.core.alerts(baseurl=target)
            
            # Save to zap_answer folder
            filename = os.path.join(DIR_RAW, f"reporte_raw.json")
            
            with open(filename, 'w') as f:
                json.dump(alerts, f)
            
            self.last_report_file = filename
            self.log(f"✅ Reporte guardado: {filename} ({len(alerts)} alertas)")
            return True

        except Exception as e:
            self.log(f"❌ Error en escaneo: {e}")
            return False

    def configure_zap_auth(self, target, user, password, auth_config):
        """
        Configures ZAP Context for Form-Based Authentication.
        """
        try:
            self.log("🔐 Configurando Autenticación en ZAP...")
            
            # 1. Create Context
            context_name = "AuthContext"
            self.zap.context.new_context(context_name)
            ctx_id = self.zap.context.context(context_name)['id']
            
            # 2. Include Target in Context
            self.zap.context.include_in_context(context_name, f"{target}.*")
            
            # 3. Method: Form-Based
            raw_login = auth_config.get('login_url')
            if not raw_login: raw_login = 'login' # Fallback if None or empty
            
            login_url = target.rstrip("/") + "/" + raw_login.lstrip("/")
            # POST Data string: username={%username%}&password={%password%}
            user_field = auth_config.get('username_field', 'email')
            pass_field = auth_config.get('password_field', 'password')
            
            login_request_data = f"{user_field}={{%username%}}&{pass_field}={{%password%}}"
            
            self.zap.authentication.set_authentication_method(
                contextid=ctx_id,
                authmethodname="formBasedAuthentication",
                authmethodconfigparams=f"loginUrl={login_url}&loginRequestData={login_request_data}"
            )
            
            self.log(f"   -> Login URL: {login_url}")
            self.log(f"   -> Params: {user_field}, {pass_field}")
            
            # 4. Create User
            user_name = "ScanUser"
            userid = self.zap.users.new_user(ctx_id, user_name)
            
            # set credentials
            self.zap.users.set_authentication_credentials(
                contextid=ctx_id,
                userid=userid,
                authcredentialsconfigparams=f"username={user}&password={password}"
            )
            
            self.zap.users.set_user_enabled(ctx_id, userid, "true")
            self.zap.forcedUser.set_forced_user(ctx_id, userid)
            self.zap.forcedUser.set_forced_user_mode_enabled(True)
            
            self.log(f"✅ Autenticación Configurada (Usuario: {user})")
            
        except Exception as e:
            self.log(f"⚠️ Fallo al configurar Auth: {e}")

    def run_ai_analysis(self, json_file, api_key):
        self.log(f"--- FASE 2: ANÁLISIS IA ---")
        self.update_status("Iniciando análisis inteligente...", "purple")
        self.update_ai_progress(0.05) 

        # Here we will call the separate AI logic (simulated for now until we link the file)
        # Import dynamically to ensure reload
        try:
            import ai_analyzer
            
            # Context
            tech_stack = self.tech_stack_entry.get()
            is_local = self.is_local_var.get()
            
            # Callback for progress bar
            def progress_callback(pct):
                # map 0-100 of AI 
                val = pct / 100.0
                self.update_ai_progress(val)
                self.update_status(f"Analizando con IA... {int(pct)}%", "purple")

            output_file = ai_analyzer.analyze_report(
                json_path=json_file, 
                api_key=api_key, 
                tech_stack=tech_stack, 
                is_local=is_local,
                log_func=self.log,
                progress_func=progress_callback
            )

            if output_file:
                self.log(f"✨ ANÁLISIS COMPLETADO.")
                self.update_ai_progress(1.0)
                self.after(0, lambda: tkinter.messagebox.showinfo("Éxito", "¡Análisis Inteligente Terminado!\nAbre el reporte."))
        
        except ImportError:
            self.log("❌ Falta el módulo ai_analyzer.py (próximo paso)")
        except Exception as e:
            self.log(f"❌ Error IA: {e}")

if __name__ == "__main__":
    ctk.set_appearance_mode("Light") # Google Style: Light Mode
    ctk.set_default_color_theme("blue") 
    app = VulnerabilityScannerApp()
    app.mainloop()
