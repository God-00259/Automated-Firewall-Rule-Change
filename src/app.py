from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'firewall-workflow-secret-key-2024'
DATABASE = 'firewall_workflow.db'

# ───────────────────────────────────────────────
# DATABASE SETUP
# ───────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            full_name TEXT NOT NULL
        )
    ''')
    
    # Firewall requests table
    c.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            action TEXT NOT NULL,
            reason TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            firewall_command TEXT,
            created_at TEXT NOT NULL,
            approved_by INTEGER,
            approved_at TEXT,
            rejected_by INTEGER,
            rejected_at TEXT,
            rejection_reason TEXT,
            implemented_at TEXT,
            rolled_back INTEGER DEFAULT 0,
            rolled_back_at TEXT,
            rolled_back_by INTEGER
        )
    ''')
    
    # Audit log table (immutable record)
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            performed_by INTEGER NOT NULL,
            performed_by_name TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            details TEXT NOT NULL
        )
    ''')
    
    # Insert default users if none exist
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        default_users = [
            ('john_doe', 'requester', 'John Doe (Requester)'),
            ('security_sarah', 'security_officer', 'Sarah Smith (Security)'),
            ('admin_mike', 'admin', 'Mike Johnson (Admin)'),
        ]
        for username, role, full_name in default_users:
            c.execute(
                "INSERT INTO users (username, password, role, full_name) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash('password123'), role, full_name)
            )
    
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# ───────────────────────────────────────────────
# RISK SCORING ENGINE (Your "Secret Sauce")
# ───────────────────────────────────────────────
def calculate_risk(source_ip, destination_ip, port, protocol, action):
    """
    Smart risk calculator — makes your project unique!
    Returns: (score 0-10, level 'LOW'/'MEDIUM'/'HIGH')
    """
    score = 0
    
    # Dangerous ports (higher = riskier)
    dangerous_ports = [22, 23, 25, 53, 110, 143, 445, 3389, 5432, 3306]
    very_dangerous = [22, 23, 445, 3389]  # SSH, Telnet, SMB, RDP
    
    if port in very_dangerous:
        score += 4
    elif port in dangerous_ports:
        score += 2
    elif port < 1024:
        score += 1
    
    # External exposure is risky
    if source_ip == '0.0.0.0/0' or source_ip.lower() == 'any':
        score += 3
    elif source_ip.startswith('10.') or source_ip.startswith('192.168.') or source_ip.startswith('172.'):
        score += 0  # Internal = safe
    else:
        score += 2  # Specific external IP = medium risk
    
    # Protocol risk
    if protocol.upper() == 'TCP':
        score += 0
    elif protocol.upper() == 'UDP':
        score += 1
    elif protocol.upper() == 'ICMP':
        score += 0
    else:
        score += 1
    
    # Action: DENY is always safer than ALLOW
    if action.upper() == 'DROP' or action.upper() == 'DENY':
        score -= 2
    
    # Clamp score between 0 and 10
    score = max(0, min(10, score))
    
    if score <= 3:
        level = 'LOW'
    elif score <= 6:
        level = 'MEDIUM'
    else:
        level = 'HIGH'
    
    return score, level

def generate_firewall_command(source_ip, destination_ip, port, protocol, action):
    """Generate a realistic iptables command"""
    src = source_ip if source_ip else '0.0.0.0/0'
    dst = destination_ip if destination_ip else '0.0.0.0/0'
    act = 'ACCEPT' if action.upper() == 'ALLOW' else 'DROP'
    
    if port == 0 or port is None:
        cmd = f"iptables -A INPUT -s {src} -d {dst} -p {protocol.lower()} -j {act}"
    else:
        cmd = f"iptables -A INPUT -s {src} -d {dst} -p {protocol.lower()} --dport {port} -j {act}"
    return cmd

def add_audit_entry(request_id, action, user_id, user_name, details):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (request_id, action, performed_by, performed_by_name, timestamp, details) VALUES (?, ?, ?, ?, ?, ?)",
        (request_id, action, user_id, user_name, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), details)
    )
    conn.commit()
    conn.close()

# ───────────────────────────────────────────────
# ROUTES
# ───────────────────────────────────────────────

@app.route('/')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    
    # Stats for dashboard
    total_requests = conn.execute("SELECT COUNT(*) as count FROM requests").fetchone()['count']
    pending = conn.execute("SELECT COUNT(*) as count FROM requests WHERE status = 'pending'").fetchone()['count']
    approved = conn.execute("SELECT COUNT(*) as count FROM requests WHERE status = 'approved'").fetchone()['count']
    rejected = conn.execute("SELECT COUNT(*) as count FROM requests WHERE status = 'rejected'").fetchone()['count']
    high_risk = conn.execute("SELECT COUNT(*) as count FROM requests WHERE risk_level = 'HIGH'").fetchone()['count']
    
    # Recent requests
    recent = conn.execute(
        "SELECT r.*, u.full_name as requester_name FROM requests r JOIN users u ON r.requester_id = u.id ORDER BY r.created_at DESC LIMIT 5"
    ).fetchall()
    
    conn.close()
    
    return render_template('index.html', user=user, stats={
        'total': total_requests,
        'pending': pending,
        'approved': approved,
        'rejected': rejected,
        'high_risk': high_risk
    }, recent=recent)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            flash(f"Welcome, {user['full_name']}!")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for('login'))

@app.route('/request', methods=['GET', 'POST'])
def new_request():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        source_ip = request.form['source_ip']
        destination_ip = request.form['destination_ip']
        port = int(request.form['port']) if request.form['port'] else 0
        protocol = request.form['protocol']
        action = request.form['action']
        reason = request.form['reason']
        
        # Calculate risk
        risk_score, risk_level = calculate_risk(source_ip, destination_ip, port, protocol, action)
        
        # Generate firewall command
        fw_cmd = generate_firewall_command(source_ip, destination_ip, port, protocol, action)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO requests 
            (requester_id, title, source_ip, destination_ip, port, protocol, action, reason, 
             risk_score, risk_level, firewall_command, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], title, source_ip, destination_ip, port, protocol, action, reason,
              risk_score, risk_level, fw_cmd, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        
        request_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Add audit entry
        add_audit_entry(request_id, 'REQUEST_CREATED', session['user_id'], session['full_name'],
                       f"Request submitted with risk score {risk_score}/10 ({risk_level})")
        
        flash(f"Request submitted! Risk Score: {risk_score}/10 ({risk_level}). Waiting for approval.")
        return redirect(url_for('dashboard'))
    
    return render_template('request_form.html')

@app.route('/approve')
def approve_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Only security officers and admins can approve
    if session['role'] not in ['security_officer', 'admin']:
        flash("You don't have permission to approve requests.")
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    
    # Get pending requests with requester info
    requests_list = conn.execute('''
        SELECT r.*, u.full_name as requester_name 
        FROM requests r 
        JOIN users u ON r.requester_id = u.id 
        WHERE r.status = 'pending'
        ORDER BY r.risk_score DESC, r.created_at ASC
    ''').fetchall()
    
    conn.close()
    return render_template('approve.html', requests=requests_list)

@app.route('/approve/<int:req_id>', methods=['POST'])
def approve_request(req_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session['role'] not in ['security_officer', 'admin']:
        flash("Permission denied.")
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (req_id,)).fetchone()
    
    if not req:
        flash("Request not found.")
        return redirect(url_for('approve_list'))
    
    if req['requester_id'] == session['user_id']:
        flash("Four-Eyes Principle: You cannot approve your own request!")
        return redirect(url_for('approve_list'))
    
    # Approve it
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute('''
        UPDATE requests 
        SET status = 'approved', approved_by = ?, approved_at = ?, implemented_at = ?
        WHERE id = ?
    ''', (session['user_id'], now, now, req_id))
    conn.commit()
    conn.close()
    
    add_audit_entry(req_id, 'APPROVED_AND_IMPLEMENTED', session['user_id'], session['full_name'],
                   f"Request approved by {session['full_name']}. Firewall command executed: {req['firewall_command']}")
    
    flash(f"Request #{req_id} approved and implemented successfully!")
    return redirect(url_for('approve_list'))

@app.route('/reject/<int:req_id>', methods=['POST'])
def reject_request(req_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session['role'] not in ['security_officer', 'admin']:
        flash("Permission denied.")
        return redirect(url_for('dashboard'))
    
    reason = request.form.get('rejection_reason', 'No reason provided')
    
    conn = get_db()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute('''
        UPDATE requests 
        SET status = 'rejected', rejected_by = ?, rejected_at = ?, rejection_reason = ?
        WHERE id = ?
    ''', (session['user_id'], now, reason, req_id))
    conn.commit()
    conn.close()
    
    add_audit_entry(req_id, 'REJECTED', session['user_id'], session['full_name'],
                   f"Request rejected. Reason: {reason}")
    
    flash(f"Request #{req_id} rejected.")
    return redirect(url_for('approve_list'))

@app.route('/rollback/<int:req_id>', methods=['POST'])
def rollback_request(req_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session['role'] != 'admin':
        flash("Only admins can rollback changes.")
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (req_id,)).fetchone()
    
    if not req or req['status'] != 'approved':
        flash("Can only rollback approved requests.")
        return redirect(url_for('audit_trail'))
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute('''
        UPDATE requests 
        SET rolled_back = 1, rolled_back_at = ?, rolled_back_by = ?
        WHERE id = ?
    ''', (now, session['user_id'], req_id))
    conn.commit()
    conn.close()
    
    rollback_cmd = req['firewall_command'].replace('-A', '-D')  # Delete the rule
    add_audit_entry(req_id, 'ROLLED_BACK', session['user_id'], session['full_name'],
                   f"Rule rolled back by admin. Rollback command: {rollback_cmd}")
    
    flash(f"Request #{req_id} has been rolled back!")
    return redirect(url_for('audit_trail'))

@app.route('/audit')
def audit_trail():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    
    # Get all requests with full details
    requests_list = conn.execute('''
        SELECT r.*, 
               req.full_name as requester_name,
               apr.full_name as approver_name,
               rej.full_name as rejecter_name,
               rb.full_name as rollbacker_name
        FROM requests r
        LEFT JOIN users req ON r.requester_id = req.id
        LEFT JOIN users apr ON r.approved_by = apr.id
        LEFT JOIN users rej ON r.rejected_by = rej.id
        LEFT JOIN users rb ON r.rolled_back_by = rb.id
        ORDER BY r.created_at DESC
    ''').fetchall()
    
    # Get audit log entries
    audit_entries = conn.execute('''
        SELECT a.*, r.title as request_title
        FROM audit_log a
        JOIN requests r ON a.request_id = r.id
        ORDER BY a.timestamp DESC
        LIMIT 50
    ''').fetchall()
    
    conn.close()
    return render_template('audit.html', requests=requests_list, audit_entries=audit_entries)

@app.route('/request/<int:req_id>')
def view_request(req_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    req = conn.execute('''
        SELECT r.*, req.full_name as requester_name,
               apr.full_name as approver_name,
               rej.full_name as rejecter_name
        FROM requests r
        LEFT JOIN users req ON r.requester_id = req.id
        LEFT JOIN users apr ON r.approved_by = apr.id
        LEFT JOIN users rej ON r.rejected_by = rej.id
        WHERE r.id = ?
    ''', (req_id,)).fetchone()
    
    audit = conn.execute(
        "SELECT * FROM audit_log WHERE request_id = ? ORDER BY timestamp ASC",
        (req_id,)
    ).fetchall()
    
    conn.close()
    
    if not req:
        flash("Request not found.")
        return redirect(url_for('dashboard'))
    
    return render_template('request_detail.html', req=req, audit=audit)

# ───────────────────────────────────────────────
# MAIN
# ───────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    print("=" * 60)
    print("🔥 FIREWALL RULE CHANGE MANAGEMENT SYSTEM")
    print("=" * 60)
    print("Default login credentials:")
    print("  Requester:     john_doe / password123")
    print("  Security:      security_sarah / password123")
    print("  Admin:         admin_mike / password123")
    print("=" * 60)
    print("Open your browser and go to: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
