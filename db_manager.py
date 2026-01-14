import sqlite3
import os
from datetime import datetime

DB_NAME = "scans_history.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  date TEXT,
                  url TEXT,
                  risk_critical INTEGER,
                  risk_high INTEGER,
                  risk_medium INTEGER,
                  risk_low INTEGER,
                  total_alerts INTEGER,
                  report_path TEXT)''')
    conn.commit()
    conn.close()

def add_scan(url, stats, report_path):
    """
    stats: dict {5: count, 4: count, ...}
    """
    try:
        init_db()
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Calculate totals from stats dict (keys match ZAP risks: 3=High in specific mapping or 5=Crit in our AI mapping)
        # AI Analyzer uses: 5=Crit, 4=High, 3=Med, 2=Low, 1=Info
        
        c.execute("INSERT INTO scans (date, url, risk_critical, risk_high, risk_medium, risk_low, total_alerts, report_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                  (date_str, 
                   url, 
                   stats.get(5, 0), 
                   stats.get(4, 0), 
                   stats.get(3, 0), 
                   stats.get(2, 0) + stats.get(1, 0), # Low + Info
                   sum(stats.values()), 
                   report_path))
        
        conn.commit()
        conn.close()
        print(f"✅ [DB] Scan saved to history: {url}")
    except Exception as e:
        print(f"❌ [DB] Error saving scan: {e}")

def get_history():
    try:
        if not os.path.exists(DB_NAME): return []
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM scans ORDER BY id DESC")
        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return rows
    except:
        return []
