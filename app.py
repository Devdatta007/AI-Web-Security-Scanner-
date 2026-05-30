from flask import Flask, request, jsonify, render_template, Response, send_file, session, redirect, url_for
import os
import time
import json
import queue
import uuid
import threading
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# Local modules
from scanner import scan_target, analyze_headers, compile_scan_summary, find_subdomains
from ai_reporter import generate_ai_report
from report_generator import generate_pdf_report
from database import get_user_by_username, create_user, save_report, get_report, get_reports_by_user, init_db

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'sec-audit-super-secret-key-2026')

# Ensure DB tables exist on startup
with app.app_context():
    init_db()

# Global dictionary for ephemeral state (logs)
scan_logs = {}
# Ephemeral cache for very recent results; long-term results handled by SQLite
scan_results_cache = {}

def stream_logs(scan_id):
    """Generator for Server-Sent Events with keep-alive."""
    # If it's already in results, just send EOF immediately so the client can fetch results
    if scan_id in scan_results_cache:
        yield f"data: {json.dumps({'message': 'EOF'})}\n\n"
        return

    q = scan_logs.get(scan_id)
    if not q:
        yield f"data: {json.dumps({'message': 'Scan session not found or expired.'})}\n\n"
        yield f"data: {json.dumps({'message': 'EOF'})}\n\n"
        return

    while True:
        try:
            # Frequent heartbeats to keep connection alive during AI phases
            msg = q.get(timeout=3) 
            if msg == "EOF":
                yield f"data: {json.dumps({'message': 'EOF'})}\n\n"
                break
            yield f"data: {json.dumps({'message': msg})}\n\n"
        except queue.Empty:
            # Check if it finished while waiting
            if scan_id in scan_results_cache:
                yield f"data: {json.dumps({'message': 'EOF'})}\n\n"
                break
            yield ": heartbeat\n\n"
        except Exception:
            yield f"data: {json.dumps({'message': 'EOF'})}\n\n"
            break


@app.before_request
def require_login():
    # results and stream are partially bypassed for recovery robustness
    # check is still performed inside those routes if needed
    allowed_routes = ['login', 'register', 'static', 'chrome_devtools_config', 'get_results', 'stream']
    if 'user_id' not in session and request.endpoint not in allowed_routes:
        return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('index.html', username=session.get('username'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = get_user_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        return redirect(url_for('login', error='Invalid Identity or Signature'))
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    if not username or not password:
        return redirect(url_for('login', error='Identity and Signature required'))
    
    hashed_pw = generate_password_hash(password)
    if create_user(username, hashed_pw):
        return redirect(url_for('login', error='Node Initialized. Please Establish Link.'))
    return redirect(url_for('login', error='Identity already exists in network'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/.well-known/appspecific/com.chrome.devtools.json')
def chrome_devtools_config():
    # Silencing Chrome DevTools 404 noise
    return jsonify({}), 200

@app.route('/stream/<scan_id>')
def stream(scan_id):
    return Response(stream_logs(scan_id), mimetype='text/event-stream')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    if not data:
        return jsonify({"status": "error", "message": "Invalid payload"}), 400
        
    url = data.get('url')
    authorized = data.get('authorized')
    
    if not url or not authorized:
        return jsonify({"status": "error", "message": "URL and Authorization required"}), 400
        
    scan_id = str(uuid.uuid4())
    scan_logs[scan_id] = queue.Queue()
    user_id = session.get('user_id') # Capture for thread
    
    def log_to_queue(msg):
        if scan_id in scan_logs:
            scan_logs[scan_id].put(msg)
    
    def run_full_scan():
        try:
            # 1. Execute Real-Time Nmap Scan
            scan_data = scan_target(url, log_callback=log_to_queue)
            
            # 2. Extract and Analyze Headers
            header_data = analyze_headers(url, log_callback=log_to_queue)

            # 3. Subdomain Reconnaissance
            subdomain_data = find_subdomains(url, log_callback=log_to_queue)
            
            # 4. Compile textual summary for AI context
            log_to_queue("🤖 Generating AI Security Report (Preparing context)...")
            scan_summary = compile_scan_summary(scan_data, header_data, subdomain_data)
            
            # 5. Generate AI report with real-time streaming
            log_to_queue("🧠 CALLING NVIDIA MISTRAL-LARGE-3 (FLAGSHIP INTELLIGENCE)...")
            ai_response = generate_ai_report(scan_summary, log_callback=log_to_queue)
            
            ai_report_content = ai_response.get('report', '') if ai_response.get('status') == 'success' else f"### AI Analysis Unfinished\n{ai_response.get('message')}"
            
            if ai_response.get('status') == 'success':
                log_to_queue(f"✨ Deep Audit complete. Intelligence report generated ({len(ai_report_content)} chars).")
            else:
                log_to_queue(f"⚠️ AI Report Warning: {ai_response.get('message')}")

            log_to_queue("✨ Scan complete!")
            
            final_result = {
                "status": "success",
                "target_url": url,
                "timestamp": time.ctime(),
                "scan_data": scan_data.get('open_ports', []) if scan_data.get('status') == 'success' else [],
                "issues": header_data.get('issues', []) if header_data.get('status') == 'success' else [],
                "subdomains": subdomain_data,
                "ai_report": ai_report_content
            }
            
            scan_results_cache[scan_id] = final_result
            
            # Persistent Storage Attempt
            try:
                save_report(scan_id, user_id, url, final_result['timestamp'], "success", final_result)
            except Exception as e:
                log_to_queue(f"⚠️ Persistence Warning: Cache is active but database write failed. Check logs.")
                
            log_to_queue("EOF")
            # Cleanup queue from memory after scan completes
            scan_logs.pop(scan_id, None)

        except Exception as e:
            log_to_queue(f"❌ Error during scan: {str(e)}")
            error_result = {
                "status": "error",
                "message": str(e),
                "target_url": url,
                "timestamp": time.ctime()
            }
            scan_results_cache[scan_id] = error_result
            save_report(scan_id, user_id, url, error_result['timestamp'], "error", error_result)
            log_to_queue("EOF")
            # Cleanup queue from memory after scan completes
            scan_logs.pop(scan_id, None)

    threading.Thread(target=run_full_scan).start()
    return jsonify({"status": "started", "scan_id": scan_id})

@app.route('/results/<scan_id>')
def get_results(scan_id):
    # Try cache first
    if scan_id in scan_results_cache:
        return jsonify(scan_results_cache[scan_id])
    
    # Try Database
    db_report = get_report(scan_id)
    if db_report:
        return jsonify(db_report['data'])

    # Scan is actively running (queue exists but result not yet ready)
    if scan_id in scan_logs:
        return jsonify({"status": "running"})
        
    return jsonify({"status": "pending"})

@app.route('/history')
def history():
    user_id = session.get('user_id')
    reports = get_reports_by_user(user_id)
    return render_template('history.html', reports=reports)

@app.route('/report/<scan_id>')
def view_report(scan_id):
    # Check cache or DB
    if scan_id in scan_results_cache or get_report(scan_id):
         return render_template('result.html', scan_id=scan_id, status='success')
    
    # Check if pending
    if scan_id in scan_logs:
         return render_template('result.html', scan_id=scan_id, status='pending')
         
    return "Scan session not found.", 404

@app.route('/download/<scan_id>')
def download_report(scan_id):
    result_data = None
    if scan_id in scan_results_cache:
        result_data = scan_results_cache[scan_id]
    else:
        db_report = get_report(scan_id)
        if db_report:
            result_data = db_report['data']
            
    if result_data:
        pdf_path = generate_pdf_report(scan_id, result_data)
        return send_file(pdf_path, as_attachment=True)
        
    return jsonify({"status": "error", "message": "Report not ready"}), 404

if __name__ == '__main__':
    # threaded=True is critical for parallel stream/worker management
    # use_reloader=False prevents watchdog from killing background scan threads mid-execution
    app.run(debug=True, port=5000, threaded=True, use_reloader=False)
