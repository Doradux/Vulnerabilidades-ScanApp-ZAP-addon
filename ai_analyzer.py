import json
import os
import google.generativeai as genai
import time
from datetime import datetime

# --- CONFIG ---
BATCH_SIZE = 5  # Alerts per split file
DIR_SPLIT = "zap_answer_split"
DIR_FINAL = "final_json"
DIR_RAW = "zap_answer"

def analyze_report(json_path, api_key, tech_stack, is_local, log_func, progress_func):
    """
    1. Reads ZAP JSON.
    2. Splits into small JSON files in 'zap_answer_split'.
    3. Analyzes each split file.
    4. Aggregates to 'final_json/analisis_final.json'.
    5. Generates Dashboard with download links.
    """
    
    # 1. Setup
    if not api_key:
        log_func("⚠️ No API Key provided. Skipping AI analysis.")
        return None
        
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.0-flash')
    except Exception as e:
        log_func(f"❌ Error configuring Gemini: {e}")
        return None
        
    # DEBUG: List models to file to see what is available
    try:
        models = [m.name for m in genai.list_models()]
        with open('models_available.txt', 'w') as f:
            f.write('\n'.join(models))
    except Exception as e:
        print(f"DEBUG: Could not list models: {e}")

    # 2. Read Internal Report
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            alerts = json.load(f)
    except Exception as e:
        log_func(f"❌ Error reading JSON: {e}")
        return None

    total_alerts = len(alerts)
    if total_alerts == 0:
        log_func("⚠️ No alerts to analyze.")
        return None
    
    # 3. SPLIT Strategy
    # Group unique alerts first to avoid redundancy
    unique_alerts = {}
    for a in alerts:
        unique_alerts[a['alert']] = a 
    
    items_to_process = list(unique_alerts.values())
    total_items = len(items_to_process)
    
    log_func(f"🧠 {total_alerts} alertas totales -> {total_items} tipos únicos para analizar.")

    # Create Split Files
    split_files = []
    num_batches = (total_items + BATCH_SIZE - 1) // BATCH_SIZE
    
    for i in range(num_batches):
        batch_start = i * BATCH_SIZE
        batch_end = min((i + 1) * BATCH_SIZE, total_items)
        batch = items_to_process[batch_start:batch_end]
        
        split_filename = os.path.join(DIR_SPLIT, f"batch_{i+1}.json")
        with open(split_filename, 'w', encoding='utf-8') as f:
            json.dump(batch, f, indent=2)
            
        split_files.append(split_filename)

    log_func(f"📂 Dividido en {len(split_files)} archivos en '{DIR_SPLIT}'.")

    # 4. Analyze loop
    final_results = []
    
    for i, split_file in enumerate(split_files):
        log_func(f"🤖 Analizando archivo {i+1}/{len(split_files)}: {os.path.basename(split_file)}...")
        
        # Read the split file
        with open(split_file, 'r', encoding='utf-8') as f:
            batch_data = json.load(f)
            
        # Prompt
        prompt = create_prompt(batch_data, tech_stack, is_local)
        
        # Call Gemini
        try:
            # Call Gemini with Retry
            response = generate_with_retry(model, prompt, log_func)
            if not response:
                raise Exception("Failed to get response after retries")
                
            json_response = clean_json_response(response.text)
            
            # Parse response
            try:
                batch_analysis = json.loads(json_response)
            except json.JSONDecodeError:
                # Fallback: Try to escape all backslashes (common AI error with Windows paths)
                try:
                    sanitized = json_response.replace("\\", "\\\\")
                    batch_analysis = json.loads(sanitized)
                except:
                    # Second fallback: Text cleanup for control chars
                    sanitized = json_response.replace("\n", " ").replace("\r", "")
                    batch_analysis = json.loads(sanitized)
            
            # Append to final list
            if isinstance(batch_analysis, list):
                final_results.extend(batch_analysis)
            else:
                 final_results.append(batch_analysis)
                 
        except Exception as e:
            msg = f"⚠️ Error analyzing batch {i+1}: {e}"
            log_func(msg)
            print(msg) # Print to console for debugging
            
            # Fallback: Add dummy entries so user sees something
            for item in batch_data:
                final_results.append({
                    "scan_alert_name": item.get('alert', 'Unknown'),
                    "human_description": f"Error en análisis IA: {str(e)}",
                    "risk_score": 1,
                    "consequence": "No se pudo analizar.",
                    "fix_code": "Verificar log."
                })
        
        # Update Progress
        pct = int(((i + 1) / len(split_files)) * 100)
        progress_func(pct)
        
        # Save Intermediate Result to FINAL folder
        final_path = os.path.join(DIR_FINAL, "analisis_final.json")
        with open(final_path, 'w', encoding='utf-8') as f:
            json.dump(final_results, f, indent=2, ensure_ascii=False)
            
        time.sleep(5) 

    # 5. Generate Dashboard
    create_dashboard_html(final_results, json_path, final_path)
    create_dashboard_html(final_results, json_path, final_path)
    return final_path

def analyze_routes_and_auth(routes_file_path, api_key, tech_stack, log_func):
    """
    Analyzes a route file (e.g. web.php) to extract:
    1. List of URLs/Routes.
    2. Authentication config (Login URL, Param names).
    """
    if not os.path.exists(routes_file_path):
        log_func(f"⚠️ Routes file not found: {routes_file_path}")
        return None

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.0-flash')
        
        with open(routes_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code_content = f.read()
            
        prompt = create_routes_prompt(code_content, tech_stack)
        
        log_func(f"🧠 Analizando archivo de rutas para descubrir endpoints y auth...")
        
        response = generate_with_retry(model, prompt, log_func)
        if not response: return None
        
        json_response = clean_json_response(response.text)
        data = json.loads(json_response)
        
        return data

    except Exception as e:
        log_func(f"❌ Error analyzing routes: {e}")
        return None

        return data

    except Exception as e:
        log_func(f"❌ Error analyzing routes: {e}")
        return None

def analyze_codebase(source_dir, api_key, tech_stack, log_func, progress_func):
    """
    SAST: Walks through source_dir, picks code files, and asks Gemini to find secrets/vulns.
    """
    log_func(f"🔍 Iniciando Análisis de Código (SAST) en: {source_dir}")
    
    # 1. Gather Files
    valid_exts = {'.py', '.php', '.js', '.ts', '.java', '.go', '.rb', '.env', '.yml', '.json', '.sql'}
    ignore_dirs = {'node_modules', 'vendor', '.git', '__pycache__', 'dist', 'build', 'venv', '.idea', '.vscode'}
    
    code_files = []
    
    for root, dirs, files in os.walk(source_dir):
        # Filter directories in-place
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        
        for file in files:
            ext = os.path.splitext(file)[1]
            if ext in valid_exts:
                code_files.append(os.path.join(root, file))

    if not code_files:
        log_func("⚠️ No se encontraron archivos de código válidos.")
        return []

    log_func(f"📄 Se analizarán {len(code_files)} archivos de código.")

    # 2. Setup Gemini
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.0-flash')
    except Exception as e:
        log_func(f"❌ Error configuring Gemini: {e}")
        return []

    # 3. Analyze in Batches (Chunking Strategy)
    # Gemini 2.0 Flash has ~1M token window. We can safely send ~100k-500k chars per request.
    # This reduces API calls from N_files to N_batches (massive speedup).
    
    all_sast_results = []
    
    current_batch_content = ""
    current_batch_files_count = 0
    BATCH_CHAR_LIMIT = 200000 # Conservative limit (approx 50k-70k tokens)
    
    # Pre-process: Read all contents efficiently
    files_data = [] # List of (rel_path, content)
    
    log_func("📦 Preparando lotes de archivos para optimizar velocidad...")
    
    for file_path in code_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if not content.strip(): continue
                if len(content) > 100000: content = content[:100000] + "\n...[TRUNCATED]"
                
                rel_path = os.path.relpath(file_path, source_dir)
                files_data.append((rel_path, content))
        except: pass

    total_files = len(files_data)
    processed_count = 0

    # Generator to yield batches
    def get_batches(data, limit):
        batch = []
        current_len = 0
        for item in data:
            item_len = len(item[1]) + len(item[0]) + 50
            if current_len + item_len > limit and batch:
                yield batch
                batch = []
                current_len = 0
            batch.append(item)
            current_len += item_len
        if batch: yield batch

    batches = list(get_batches(files_data, BATCH_CHAR_LIMIT))
    log_func(f"🚀 Optimización: {total_files} archivos agrupados en {len(batches)} peticiones a la IA.")

    for i, batch in enumerate(batches):
        pct = int(((i) / len(batches)) * 100)
        progress_func(pct)
        
        # Construct Prompt with multiple files
        batch_str = ""
        for path, code in batch:
            batch_str += f"\n--- START FILE: {path} ---\n{code}\n--- END FILE: {path} ---\n"
            
        prompt = create_sast_batch_prompt(batch_str, tech_stack)
        
        log_func(f"⚡ Analizando Lote {i+1}/{len(batches)} ({len(batch)} archivos)...")
        
        try:
            response = generate_with_retry(model, prompt, log_func, retries=2)
            if response:
                json_res = clean_json_response(response.text)
                if json_res == "[]": continue
                
                analysis = json.loads(json_res)
                if isinstance(analysis, list):
                    all_sast_results.extend(analysis)
                
                time.sleep(2) # Politeness delay
        except Exception as e:
            log_func(f"⚠️ Error en lote {i+1}: {e}")

    progress_func(100)
    log_func(f"✅ SAST Completado. {len(all_sast_results)} hallazgos.")
    
    sast_path = os.path.join(DIR_FINAL, "sast_results.json")
    with open(sast_path, 'w', encoding='utf-8') as f:
        json.dump(all_sast_results, f, indent=2, ensure_ascii=False)
        
    return all_sast_results

def create_sast_batch_prompt(batch_content, tech_stack):
    return f"""
    Role: Security Auditor.
    Task: Review the provided BATCH OF SOURCE CODE FILES ({tech_stack}) for SECURITY VULNERABILITIES.
    
    CONTEXT:
    The input contains multiple files separated by "--- START FILE: name ---" markers.
    Analyze EACH file within the batch.
    
    Look for:
    1. Hardcoded Secrets (API Keys, Passwords, AWS Keys).
    2. SQL Injection, XSS, RCE.
    3. Insecure Logic or Configurations.
    
    INPUT CODE BATCH:
    {batch_content}
    
    OUTPUT:
    Return a SINGLE JSON List of objects for all findings in this batch:
    [
        {{
            "scan_alert_name": "Issue Name",
            "human_description": "Explanation in SPANISH",
            "risk_score": 1-5,
            "consequence": "Consequence in SPANISH",
            "fix_code": "Snippet showing how to fix it",
            "affected_url": "File: <filename from the marker>"
        }}
    ]
    If no issues found, return [].
    RETURN JSON ONLY.
    """

def create_routes_prompt(code_content, tech_stack):
    return f"""
    You are a Security Engineer. Analyze the following SOURCE CODE ({tech_stack}) to extract Routes and Auth info.
    
    CODE:
    {code_content}  # Process FULL CONTENT (Gemini 2.0 Flash has 1M context)
    
    TASK:
    Return a JSON object with:
    1. "routes": A list of relative paths (strings) found in the code.
       IMPORTANT: If a route has dynamic parameters (e.g. "/users/{{id}}", "/prod/:slug"), REPLACE THEM with plausible dummy values.
       - Replace IDs with "1" (e.g. "/users/1")
       - Replace slugs with "test" (e.g. "/prod/test")
       - DO NOT return generic placeholders like "{{id}}". Return concrete, testable URLs.
    2. "auth_config": Object containing:
        - "login_url": The likely URL for the login page (e.g. "/login").
        - "username_field": The likely name of the username parameter (e.g. "email", "username").
        - "password_field": The likely name of the password parameter (e.g. "password").
        
    OUTPUT JSON ONLY.
    """

def generate_with_retry(model, prompt, log_func, retries=3):
    for i in range(retries):
        try:
            return model.generate_content(prompt)
        except Exception as e:
            if "429" in str(e) or "Quota" in str(e):
                wait_time = 65 # Force >60s wait to clear the minute-quota
                log_func(f"⏳ Límite de cuota (Free Tier). Esperando {wait_time}s para recargar...")
                time.sleep(wait_time)
            else:
                raise e # Not a rate limit error, raise immediately
    return None

def create_prompt(batch_alerts, tech_stack, is_local):
    env_str = "LOCAL DEVELOPMENT" if is_local else "PRODUCTION"
    
    alerts_str = json.dumps([{
        "name": a['alert'],
        "method": a['method'],
        "url": a['url'],
        "description": a['description']
    } for a in batch_alerts], indent=2)

    return f"""
    You are a Cybersecurity Expert. Analyze the following web vulnerabilities.
    
    CONTEXT:
    - Tech Stack: {tech_stack}
    - Environment: {env_str}
    
    TASK:
    For EACH vulnerability, return a JSON object with:
    1. "scan_alert_name": Exact name from input.
    2. "human_description": Simple explanation in SPANISH (Español).
    3. "risk_score": Integer 1 to 5 (5 is Critical).
    4. "consequence": What happens if not fixed? (in Spanish).
    5. "fix_code": Code snippet example relevant to {tech_stack}.
    6. "affected_url": The specific URL where this was found (from input 'url').
    7. "exploit_poc": A specific cURL command or URL to reproduce/test this vulnerability (Proof of Concept). Be precise.
    
    INPUT DATA:
    {alerts_str}
    
    OUTPUT FORMAT:
    Return ONLY a raw JSON List.
    """

def clean_json_response(text):
    text = text.replace("```json", "").replace("```", "").strip()
    # Attempt to fix common backslash issues in Windows paths (e.g. C:\xampp -> C:\\xampp)
    # Simple heuristic: If it fails to load, we might retry with escapes, but here we prep.
    return text

def create_dashboard_html(data, raw_path, final_json_path):
    # Sort by Risk (Desc), then URL (Asc)
    sorted_data = sorted(
        data, 
        key=lambda x: (-x.get('risk_score', 0), x.get('affected_url', ''))
    )
    json_data = json.dumps(sorted_data).replace("/", "\\/")
    
    # Calculate Stats
    stats = {5: 0, 4: 0, 3: 0, 2: 0, 1: 0, 0: 0}
    for item in sorted_data:
        s = item.get('risk_score', 0)
        stats[s] = stats.get(s, 0) + 1
        
    total_issues = len(sorted_data)

    # Relative links for download
    raw_link = os.path.basename(raw_path) if raw_path else "#"
    final_link = os.path.basename(final_json_path) if final_json_path else "#"

    html = f"""<!DOCTYPE html>
<html lang="es" class="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Vulnerabilidades IA</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {{
            darkMode: 'class',
        }}
    </script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Inter', sans-serif; transition: background-color 0.3s, color 0.3s; }}
        .glass-header {{ backdrop-filter: blur(20px); transition: background-color 0.3s, border-color 0.3s; }}
        .card-mac {{ transition: transform 0.2s ease, box-shadow 0.2s ease, background-color 0.3s, border-color 0.3s; }}
        .card-mac:hover {{ transform: translateY(-2px); }}
        .badge {{ padding: 4px 10px; border-radius: 999px; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.02em; }}
        
        /* Light Mode */
        html.light body {{ background-color: #F8F9FA; color: #1F2937; }}
        html.light .glass-header {{ background: rgba(255, 255, 255, 0.95); border-bottom: 1px solid rgba(0,0,0,0.05); }}
        html.light .card-mac {{ background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.02); border: 1px solid rgba(0,0,0,0.06); }}
        
        /* Dark Mode */
        html.dark body {{ background-color: #0F172A; color: #E2E8F0; }}
        html.dark .glass-header {{ background: rgba(15, 23, 42, 0.95); border-bottom: 1px solid rgba(255,255,255,0.05); }}
        html.dark .card-mac {{ background: #1E293B; box-shadow: 0 4px 20px rgba(0,0,0,0.2); border: 1px solid rgba(255,255,255,0.05); }}
        
        .code-block {{ font-family: 'Fira Code', monospace; }}
        
        @media print {{
            body {{ background: white !important; color: black !important; }}
            .glass-header, #themeToggle, button, a {{ display: none !important; }}
            .card-mac {{ box-shadow: none !important; border: 1px solid #ddd !important; break-inside: avoid; page-break-inside: avoid; }}
            #dashboard {{ display: block !important; }}
        }}
    </style>
</head>
<body class="antialiased">

    <!-- Navbar Sticky -->
    <div class="glass-header fixed top-0 w-full z-50">
        <div class="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
            <div class="flex items-center gap-3">
                <span class="text-2xl">🛡️</span>
                <div>
                    <h1 class="text-lg font-bold text-gray-900 dark:text-gray-100 tracking-tight">Reporte de Seguridad</h1>
                    <p class="text-xs text-gray-500 font-medium">Analizado por Gemini 2.0 Flash</p>
                </div>
            </div>
            <div class="flex items-center gap-3">
                 <button id="themeToggle" class="p-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 transition">
                    <span id="themeIcon">🌙</span>
                </button>
                <div class="h-6 w-px bg-gray-200 dark:bg-gray-700 mx-1"></div>
                <a href="{raw_link}" download class="hidden sm:flex px-4 py-2 rounded-lg bg-gray-100 hover:bg-gray-200 text-gray-700 text-sm font-medium transition gap-2">
                    📄 Raw
                </a>
                <a href="{final_link}" download class="hidden sm:flex px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium transition shadow-sm gap-2">
                    🤖 JSON IA
                </a>
                <button onclick="window.print()" class="px-4 py-2 rounded-lg bg-gray-900 hover:bg-gray-800 text-white text-sm font-medium transition shadow-sm flex items-center gap-2">
                    🖨️ PDF
                </button>
            </div>
        </div>
    </div>

    <div class="max-w-7xl mx-auto px-6 pt-32 pb-20">
    
        <!-- Summary Stats Section -->
        <div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-10">
            <!-- Total (First for visibility) -->
             <div class="bg-white dark:bg-gray-800 p-5 rounded-2xl border border-gray-200 dark:border-gray-700 flex flex-col items-center justify-center shadow-sm">
                <span class="text-4xl font-extrabold text-gray-800 dark:text-gray-100">{total_issues}</span>
                <span class="text-xs font-bold uppercase text-gray-400 tracking-wider mt-1">Total Vulnerabilidades</span>
            </div>
            
            <div class="bg-red-50 dark:bg-red-900/10 p-5 rounded-2xl border border-red-100 dark:border-red-900/30 flex flex-col items-center justify-center">
                <span class="text-3xl font-bold text-red-600 dark:text-red-400">{stats[5]}</span>
                <span class="text-xs font-semibold uppercase text-red-700/60 dark:text-red-300/60 tracking-wider">Crítico</span>
            </div>
            <div class="bg-orange-50 dark:bg-orange-900/10 p-5 rounded-2xl border border-orange-100 dark:border-orange-900/30 flex flex-col items-center justify-center">
                <span class="text-3xl font-bold text-orange-600 dark:text-orange-400">{stats[4]}</span>
                <span class="text-xs font-semibold uppercase text-orange-700/60 dark:text-orange-300/60 tracking-wider">Alto</span>
            </div>
            <div class="bg-yellow-50 dark:bg-yellow-900/10 p-5 rounded-2xl border border-yellow-100 dark:border-yellow-900/30 flex flex-col items-center justify-center">
                <span class="text-3xl font-bold text-yellow-600 dark:text-yellow-400">{stats[3]}</span>
                <span class="text-xs font-semibold uppercase text-yellow-700/60 dark:text-yellow-300/60 tracking-wider">Medio</span>
            </div>
            <div class="bg-blue-50 dark:bg-blue-900/10 p-5 rounded-xl border border-blue-100 dark:border-blue-900/30 flex flex-col items-center justify-center">
                <span class="text-3xl font-bold text-blue-600 dark:text-blue-400">{stats[2]}</span>
                <span class="text-xs font-semibold uppercase text-blue-700/60 dark:text-blue-300/60 tracking-wider">Bajo</span>
            </div>
        </div>
    
        <!-- List Container -->
        <div id="dashboard" class="grid gap-6">
            <!-- Cards will be injected here -->
            <div class="text-center py-20 text-gray-400">Cargando reporte...</div>
        </div>
    </div>

    <script>
        const data = {json_data};
        const container = document.getElementById('dashboard');

        // Theme Toggle Logic
        const toggleBtn = document.getElementById('themeToggle');
        const themeIcon = document.getElementById('themeIcon');
        const htmlEl = document.documentElement;

        // Apply theme immediately
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {{
             htmlEl.classList.remove('light');
             htmlEl.classList.add('dark');
             themeIcon.innerText = '☀️';
        }}

        toggleBtn.addEventListener('click', () => {{
            htmlEl.classList.toggle('dark');
            htmlEl.classList.toggle('light');
            const isDark = htmlEl.classList.contains('dark');
            themeIcon.innerText = isDark ? '☀️' : '🌙';
        }});

        // Color Maps
        const riskColors = {{
            5: {{ bg: 'bg-red-50 dark:bg-red-900/20', text: 'text-red-700 dark:text-red-300', border: 'border-red-100 dark:border-red-800', dot: 'bg-red-500' }},
            4: {{ bg: 'bg-orange-50 dark:bg-orange-900/20', text: 'text-orange-700 dark:text-orange-300', border: 'border-orange-100 dark:border-orange-800', dot: 'bg-orange-500' }},
            3: {{ bg: 'bg-yellow-50 dark:bg-yellow-900/20', text: 'text-yellow-700 dark:text-yellow-300', border: 'border-yellow-100 dark:border-yellow-800', dot: 'bg-yellow-500' }},
            2: {{ bg: 'bg-blue-50 dark:bg-blue-900/20', text: 'text-blue-700 dark:text-blue-300', border: 'border-blue-100 dark:border-blue-800', dot: 'bg-blue-500' }},
            1: {{ bg: 'bg-gray-50 dark:bg-gray-800', text: 'text-gray-600 dark:text-gray-400', border: 'border-gray-100 dark:border-gray-700', dot: 'bg-gray-400' }},
            0: {{ bg: 'bg-gray-50 dark:bg-gray-800', text: 'text-gray-600 dark:text-gray-400', border: 'border-gray-100 dark:border-gray-700', dot: 'bg-gray-400' }}
        }};

        // Optimization: Build HTML string first, then inject
        let htmlContent = '';
        
        data.forEach((item, index) => {{
            const score = item.risk_score || 0;
            const theme = riskColors[score] || riskColors[0];
            const exploit = item.exploit_poc ? `<div class="mt-4 p-3 bg-gray-100 dark:bg-gray-800 rounded-lg text-xs font-mono break-all border border-gray-200 dark:border-gray-700"><span class="text-orange-600 dark:text-orange-400 font-bold">💥 PoC:</span> ${{item.exploit_poc}}</div>` : '';
            
            const card = `
                <div class="card-mac p-6 group relative overflow-hidden">
                    <div class="absolute -right-4 -top-4 text-[100px] font-bold text-gray-50 dark:text-gray-800/30 pointer-events-none select-none -z-0">
                        #${{index + 1}}
                    </div>
                
                    <div class="relative z-10">
                        <div class="flex flex-col sm:flex-row justify-between items-start gap-4 mb-4">
                             <div class="w-full">
                                <div class="flex flex-wrap items-center gap-2 mb-2">
                                    <span class="text-gray-400 dark:text-gray-500 font-mono text-xs font-bold mr-1">#${{index + 1}}</span>
                                    <span class="badge ${{theme.bg}} ${{theme.text}} border ${{theme.border}} flex items-center gap-1.5 shrink-0">
                                        <span class="w-1.5 h-1.5 rounded-full ${{theme.dot}}"></span>
                                        Nivel ${{score}}
                                    </span>
                                    <span class="text-xs font-mono text-gray-500 dark:text-gray-400 px-2 py-0.5 break-all bg-gray-50 dark:bg-gray-800 rounded border border-gray-100 dark:border-gray-700">
                                        ${{item.affected_url || 'URL Global'}}
                                    </span>
                                </div>
                                <h2 class="text-lg sm:text-xl font-bold text-gray-900 dark:text-gray-100 leading-tight">
                                    ${{item.scan_alert_name}}
                                </h2>
                            </div>
                        </div>
                        
                        <div class="grid lg:grid-cols-2 gap-6 mt-4">
                            <div class="space-y-4">
                                <div>
                                    <h3 class="text-[10px] uppercase tracking-wider font-bold text-gray-400 mb-1 flex items-center gap-2">
                                        ANÁLISIS
                                    </h3>
                                    <p class="text-sm text-gray-600 dark:text-gray-300 leading-relaxed">${{item.human_description}}</p>
                                    ${{exploit}}
                                </div>
                                <div>
                                    <h3 class="text-[10px] uppercase tracking-wider font-bold text-gray-400 mb-1 flex items-center gap-2">
                                        CONSECUENCIAS
                                    </h3>
                                    <p class="text-sm text-gray-600 dark:text-gray-300 leading-relaxed">${{item.consequence}}</p>
                                </div>
                            </div>

                            <div class="bg-[#1e1e1e] rounded-lg overflow-hidden shadow-sm border border-gray-800 flex flex-col h-full min-h-[150px]">
                                 <div class="flex items-center justify-between px-3 py-1.5 bg-[#252526] border-b border-gray-800">
                                    <span class="text-[10px] text-gray-400 font-mono font-bold">SUGGESTED FIX</span>
                                    <div class="flex gap-1">
                                        <div class="w-2 h-2 rounded-full bg-[#EC6A5E]"></div>
                                        <div class="w-2 h-2 rounded-full bg-[#F4BF4F]"></div>
                                        <div class="w-2 h-2 rounded-full bg-[#61C554]"></div>
                                    </div>
                                </div>
                                <pre class="p-3 text-[11px] text-gray-300 font-mono overflow-x-auto whitespace-pre-wrap code-block flex-1 custom-scrollbar"><code>${{item.fix_code}}</code></pre>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            htmlContent += card;
        }});
        
        container.innerHTML = htmlContent;
    </script>
</body>
</html>"""

    with open('dashboard.html', 'w', encoding='utf-8') as f:
        f.write(html)
