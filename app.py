import sqlite3
import datetime
import urllib.request
import json
import csv
import io
from flask import Flask, request, render_template, jsonify, Response

app = Flask(__name__)
DB_FILE = "logs.db"
ADMIN_KEY = "admin123"

def init_db():
    """Initialize SQLite database table with upgraded schema."""
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

def log_connection(ip, user_agent, path, visitor_name="Anonymous"):
    """Save connection log with GeoIP resolution."""
    geo = fetch_geoip(ip)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO access_logs (visitor_name, ip_address, user_agent, country, country_code, city, isp, path, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        visitor_name, ip, user_agent,
        geo['country'], geo['country_code'], geo['city'], geo['isp'],
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
    """Enable CORS so local file:// pages can fetch API endpoints."""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

def check_admin_auth():
    """Verify admin key authentication."""
    provided_key = request.args.get('key') or request.headers.get('X-Admin-Key')
    return provided_key == ADMIN_KEY

@app.route('/')
def index():
    """Public landing page route."""
    client_ip = get_client_public_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    return render_template('index.html', client_ip=client_ip, user_agent=user_agent)

@app.route('/api/submit_name', methods=['POST'])
def submit_name():
    """API endpoint to record visitor name and log entry."""
    data = request.get_json() or {}
    visitor_name = data.get('name', 'Anonymous').strip() or 'Anonymous'
    client_ip = get_client_public_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    log_id = log_connection(client_ip, user_agent, '/', visitor_name=visitor_name)
    
    return jsonify({
        'status': 'success',
        'message': 'Visitor name logged successfully',
        'log_id': log_id,
        'visitor_name': visitor_name
    })

@app.route('/admin')
def admin_dashboard():
    """Admin Dashboard UI route with key authentication."""
    if not check_admin_auth():
        return """
        <body style="font-family: sans-serif; background: #080c14; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh;">
            <div style="background: rgba(15, 23, 42, 0.9); border: 1px solid #ef4444; padding: 2.5rem; border-radius: 20px; text-align: center; max-width: 400px;">
                <h2 style="color: #ef4444; margin-bottom: 0.5rem;">🔒 Access Denied</h2>
                <p style="color: #94a3b8; margin-bottom: 1.5rem;">Admin authentication key required.</p>
                <form action="/admin" method="GET">
                    <input type="password" name="key" placeholder="Enter Secret Admin Key" style="width: 100%; padding: 0.8rem; border-radius: 10px; border: 1px solid #3b82f6; background: #000; color: #fff; margin-bottom: 1rem;">
                    <button type="submit" style="width: 100%; padding: 0.8rem; background: #3b82f6; color: #fff; border: none; border-radius: 10px; font-weight: 600; cursor: pointer;">Login to Dashboard</button>
                </form>
            </div>
        </body>
        """, 403

    return render_template('admin.html')

@app.route('/api/stats')
def get_stats():
    """API endpoint returning analytics metrics."""
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
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Device / Browser Breakdown
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

    # Hourly Visits (Last 7 Days)
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
    """API endpoint returning connection log entries with GeoIP and Flag emojis."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, visitor_name, ip_address, user_agent, country, country_code, city, isp, timestamp, path FROM access_logs ORDER BY id DESC LIMIT 200')
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
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, visitor_name, ip_address, country, city, isp, user_agent, path, timestamp FROM access_logs ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Visitor Name', 'IP Address', 'Country', 'City', 'ISP', 'User Agent', 'Path', 'Timestamp'])
    
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
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM access_logs')
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'message': 'All access logs cleared'})

if __name__ == '__main__':
    print("🚀 Starting Flask Web App & Admin Server on http://localhost:5000")
    print("📊 Admin Dashboard (Key Auth): http://localhost:5000/admin?key=admin123")
    app.run(host='0.0.0.0', port=5000, debug=True)
