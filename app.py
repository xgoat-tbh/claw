import sqlite3
import datetime
import urllib.request
import json
import csv
import io
from flask import Flask, request, render_template, jsonify, Response, session, redirect, url_for

app = Flask(__name__)
app.secret_key = "claw_admin_secure_session_key_6767"

DB_FILE = "logs.db"
ADMIN_PASSWORD = "admin6767"

def init_db():
    """Initialize SQLite database table with upgraded schema for smart device logging."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            visitor_name TEXT DEFAULT 'Anonymous',
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            country TEXT DEFAULT 'Unknown',
            country_code TEXT DEFAULT 'UN',
            city TEXT DEFAULT 'Unknown',
            isp TEXT DEFAULT 'Unknown',
            battery TEXT DEFAULT 'N/A',
            cpu_cores TEXT DEFAULT 'N/A',
            ram_gb TEXT DEFAULT 'N/A',
            screen_res TEXT DEFAULT 'N/A',
            gpu_renderer TEXT DEFAULT 'N/A',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            path TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_country_flag(code):
    """Convert 2-letter country code to flag emoji."""
    if not code or len(code) != 2 or code == 'UN':
        return '🌐'
    return chr(ord(code[0].upper()) + 127397) + chr(ord(code[1].upper()) + 127397)

def fetch_geoip(ip):
    """Fetch country, city, and ISP for a given IP address."""
    clean_ip = ip.split(' ')[0].strip()
    if clean_ip in ('127.0.0.1', '::1', 'localhost'):
        return {'country': 'Localhost', 'country_code': 'UN', 'city': 'Local Network', 'isp': 'Loopback'}
    
    try:
        url = f"http://ip-api.com/json/{clean_ip}?fields=status,country,countryCode,city,isp"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', 'UN'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown')
                }
    except Exception:
        pass
    return {'country': 'Unknown', 'country_code': 'UN', 'city': 'Unknown', 'isp': 'Unknown'}

def log_connection(ip, user_agent, path, visitor_name="Anonymous", specs=None):
    """Save connection log with GeoIP and Smart Device Specs."""
    if specs is None:
        specs = {}
        
    geo = fetch_geoip(ip)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO access_logs 
        (visitor_name, ip_address, user_agent, country, country_code, city, isp, battery, cpu_cores, ram_gb, screen_res, gpu_renderer, path, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        visitor_name, ip, user_agent,
        geo['country'], geo['country_code'], geo['city'], geo['isp'],
        str(specs.get('battery', 'N/A')),
        str(specs.get('cpuCores', 'N/A')),
        str(specs.get('ramGb', 'N/A')),
        str(specs.get('screenRes', 'N/A')),
        str(specs.get('gpu', 'N/A')),
        path, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return log_id

def get_client_public_ip():
    """Extract client public IP."""
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()

    remote_ip = request.remote_addr
    if not remote_ip or remote_ip in ('127.0.0.1', '::1', 'localhost') or remote_ip.startswith(('192.168.', '10.', '172.16.', '172.31.')):
        try:
            with urllib.request.urlopen('https://api.ipify.org?format=text', timeout=3) as resp:
                public_ip = resp.read().decode('utf-8').strip()
                return public_ip
        except Exception:
            pass

    return remote_ip or "127.0.0.1"

# Initialize DB on startup
init_db()

@app.after_request
def add_cors_headers(response):
    """Enable CORS so local file:// and Vercel pages can fetch API endpoints."""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Admin-Key'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

def is_admin_authenticated():
    """Verify session or secret key authentication."""
    if session.get('admin_logged_in') == True:
        return True
    provided_key = request.args.get('key') or request.headers.get('X-Admin-Key')
    return provided_key == ADMIN_PASSWORD

@app.route('/')
def index():
    """Public landing page route."""
    client_ip = get_client_public_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    return render_template('index.html', client_ip=client_ip, user_agent=user_agent)

@app.route('/api/submit_name', methods=['POST'])
def submit_name():
    """API endpoint to record visitor name, smart device specs, and log entry."""
    data = request.get_json() or {}
    visitor_name = data.get('name', 'Anonymous').strip() or 'Anonymous'
    specs = data.get('specs', {})
    client_ip = get_client_public_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    log_id = log_connection(client_ip, user_agent, '/', visitor_name=visitor_name, specs=specs)
    
    return jsonify({
        'status': 'success',
        'message': 'Visitor details logged successfully',
        'log_id': log_id,
        'visitor_name': visitor_name
    })

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    """Admin Dashboard UI route with password protection (admin6767)."""
    error_msg = None

    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error_msg = "Incorrect password. Access denied."

    key_param = request.args.get('key')
    if key_param == ADMIN_PASSWORD:
        session['admin_logged_in'] = True

    if session.get('admin_logged_in'):
        return render_template('admin.html')

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Login</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            body {{
                font-family: 'Inter', sans-serif;
                background-color: #090d16;
                color: #f8fafc;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }}
            .login-card {{
                background: #111827;
                border: 1px solid #1f2937;
                border-radius: 16px;
                padding: 2.5rem 2rem;
                max-width: 380px;
                width: 90%;
                text-align: center;
            }}
            .lock-icon {{ font-size: 2.8rem; margin-bottom: 0.5rem; }}
            h2 {{ font-size: 1.6rem; font-weight: 700; margin-bottom: 0.4rem; }}
            p {{ color: #9ca3af; font-size: 0.88rem; margin-bottom: 1.6rem; }}
            input {{
                width: 100%;
                padding: 0.85rem 1rem;
                box-sizing: border-box;
                background: #030712;
                border: 1px solid #374151;
                border-radius: 10px;
                color: #fff;
                font-size: 0.95rem;
                outline: none;
                margin-bottom: 1.2rem;
            }}
            input:focus {{ border-color: #3b82f6; }}
            button {{
                width: 100%;
                padding: 0.85rem;
                background: #2563eb;
                color: #fff;
                border: none;
                border-radius: 10px;
                font-weight: 600;
                font-size: 0.95rem;
                cursor: pointer;
            }}
            button:hover {{ background: #1d4ed8; }}
            .error {{
                background: rgba(239, 68, 68, 0.1);
                color: #f87171;
                border: 1px solid rgba(239, 68, 68, 0.3);
                padding: 0.6rem;
                border-radius: 8px;
                font-size: 0.85rem;
                margin-bottom: 1rem;
            }}
        </style>
    </head>
    <body>
        <div class="login-card">
            <div class="lock-icon">🔒</div>
            <h2>Admin Portal</h2>
            <p>Enter secret password to access analytics</p>
            {f'<div class="error">{error_msg}</div>' if error_msg else ''}
            <form action="/admin" method="POST">
                <input type="password" name="password" placeholder="Admin Password..." required autofocus>
                <button type="submit">Unlock Dashboard &rarr;</button>
            </form>
        </div>
    </body>
    </html>
    """, 401

@app.route('/admin/logout')
def admin_logout():
    """Logout of Admin session."""
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_dashboard'))

@app.route('/api/stats')
def get_stats():
    """API endpoint returning analytics metrics."""
    if not is_admin_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM access_logs')
    total_visits = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(DISTINCT ip_address) FROM access_logs')
    unique_ips = cursor.fetchone()[0]
    
    today_str = datetime.date.today().strftime("%Y-%m-%d")
    cursor.execute('SELECT COUNT(*) FROM access_logs WHERE timestamp LIKE ?', (f"{today_str}%",))
    today_visits = cursor.fetchone()[0]
    
    conn.close()
    return jsonify({
        'total_visits': total_visits,
        'unique_ips': unique_ips,
        'today_visits': today_visits
    })

@app.route('/api/analytics')
def get_analytics():
    """API endpoint returning Chart.js analytics data."""
    if not is_admin_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT user_agent FROM access_logs')
    agents = [row[0] or '' for row in cursor.fetchall()]
    
    browser_counts = {'Chrome': 0, 'Firefox': 0, 'Safari': 0, 'Edge': 0, 'Other': 0}
    for ua in agents:
        if 'Edg' in ua:
            browser_counts['Edge'] += 1
        elif 'Chrome' in ua:
            browser_counts['Chrome'] += 1
        elif 'Firefox' in ua:
            browser_counts['Firefox'] += 1
        elif 'Safari' in ua:
            browser_counts['Safari'] += 1
        else:
            browser_counts['Other'] += 1

    cursor.execute('''
        SELECT strftime('%Y-%m-%d %H:00', timestamp) as hr, COUNT(*) 
        FROM access_logs 
        GROUP BY hr 
        ORDER BY hr DESC LIMIT 12
    ''')
    hourly_rows = cursor.fetchall()
    conn.close()
    
    hourly_rows.reverse()
    timeline_labels = [row[0] for row in hourly_rows]
    timeline_counts = [row[1] for row in hourly_rows]

    return jsonify({
        'browsers': browser_counts,
        'timeline': {
            'labels': timeline_labels,
            'data': timeline_counts
        }
    })

@app.route('/api/logs')
def get_logs():
    """API endpoint returning connection log entries with smart device specs."""
    if not is_admin_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, visitor_name, ip_address, user_agent, country, country_code, city, isp, battery, cpu_cores, ram_gb, screen_res, gpu_renderer, timestamp, path FROM access_logs ORDER BY id DESC LIMIT 200')
    rows = cursor.fetchall()
    conn.close()
    
    logs = []
    for row in rows:
        item = dict(row)
        item['flag'] = get_country_flag(item.get('country_code', 'UN'))
        logs.append(item)

    return jsonify(logs)

@app.route('/api/logs/export')
def export_csv():
    """Export all access logs as a downloadable CSV file."""
    if not is_admin_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, visitor_name, ip_address, country, city, isp, battery, cpu_cores, ram_gb, screen_res, gpu_renderer, user_agent, path, timestamp FROM access_logs ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Visitor Name', 'IP Address', 'Country', 'City', 'ISP', 'Battery', 'CPU Cores', 'RAM (GB)', 'Screen Res', 'GPU', 'User Agent', 'Path', 'Timestamp'])
    
    for row in rows:
        writer.writerow(list(row))
        
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=access_logs.csv"}
    )

@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    """API endpoint to wipe log history."""
    if not is_admin_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM access_logs')
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'message': 'All access logs cleared'})

if __name__ == '__main__':
    print("🚀 Starting Flask Web App & Admin Server on http://localhost:5000")
    print("🔒 Admin Password: admin6767")
    app.run(host='0.0.0.0', port=5000, debug=True)
