# 🔥 Automated Firewall Rule Change Management & Approval Workflow

> A student-built, fully functional prototype for Network Security, Auditing and Monitoring coursework. 
> Blue Team defensive security project demonstrating secure change control, risk-based approval, and immutable audit trails.

---

## 📖 What Is This?

This is a **web-based system** that acts like a "digital security desk" for firewall changes. Instead of someone emailing *"Hey, open port 443 please"* and another person manually typing commands into a server, this system:

1. **Captures** requests through a standardized form
2. **Scores** the risk automatically (like AlgoSec/Tufin, but simpler)
3. **Routes** requests to the right approver based on danger level
4. **Enforces** the "Four-Eyes Principle" (you can't approve your own request)
5. **Implements** the rule (simulated) and logs everything permanently
6. **Allows rollback** if something goes wrong

---

## 🆚 Comparison with Real Market Tools

| Feature | AlgoSec / Tufin / FireMon | **Your Prototype** |
|---------|---------------------------|-------------------|
| Cost | $30,000+ per year | **Free / Open Source** |
| Risk Scoring | AI-powered, 100+ factors | **Smart heuristic engine** (port + exposure + protocol) |
| Approval Workflow | Multi-level, ITSM integrated | **Role-based with auto-routing** |
| Four-Eyes Principle | Yes | **Yes + enforced in code** |
| Rollback | Yes, complex | **One-click, instant** |
| Audit Trail | Enterprise reports | **Beautiful security timeline** |
| Setup Time | Weeks with consultants | **Minutes on any laptop** |
| Firewall Support | Cisco, Palo Alto, Check Point, etc. | **Linux iptables (simulated)** |

**Your edge:** While enterprise tools are boring black boxes, your prototype is **transparent, visual, and demonstrates the security concepts clearly** — perfect for academic demonstration.

---

## 🚀 How to Run

### Step 1: Install Python (if not installed)
Download from [python.org](https://python.org). You need Python 3.8 or higher.

### Step 2: Install Dependencies
```bash
cd firewall-workflow
pip install -r requirements.txt
```

### Step 3: Run the Application
```bash
python app.py
```

### Step 4: Open Your Browser
Go to: **http://127.0.0.1:5000**

---

## 🔑 Demo Accounts

| Username | Password | Role | What They Can Do |
|----------|----------|------|------------------|
| `john_doe` | `password123` | Requester | Submit new firewall change requests |
| `security_sarah` | `password123` | Security Officer | Review and approve/reject requests |
| `admin_mike` | `password123` | Admin | Everything + Rollback changes |

---

## 🎯 Unique Features That Make This Exceptional

### 1. 🔥 Auto Risk Scoring Engine
Not just a form — it **thinks**:
- Port 22 (SSH) open to Internet = **9/10 HIGH RISK**
- Port 443 (HTTPS) internal = **2/10 LOW RISK**
- DROP rules automatically get lower scores than ALLOW rules

### 2. 🛡️ Four-Eyes Principle (Enforced)
The code literally prevents you from approving your own request. This is a **separation of duties** control required by most security frameworks.

### 3. ⏪ One-Click Rollback
Every approved change can be instantly undone. The system generates the reverse command automatically (`-A` becomes `-D` in iptables).

### 4. 📊 Security Timeline
Instead of boring log tables, you get a **visual timeline** showing exactly who did what, when, and why — just like GitHub's commit history but for security changes.

### 5. 📝 Immutable Audit Trail
Every action is written to a separate audit table that represents a **write-once record**. In a real system, this would be append-only storage (like a blockchain or WORM drive).

---

## 🏗️ System Architecture

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Browser   │────▶│  Flask Web App  │────▶│  SQLite Database│
│  (User)     │◀────│  (Python)       │◀────│  (Rules + Logs) │
└─────────────┘     └─────────────────┘     └─────────────────┘
                            │
                            ▼
                    ┌─────────────────┐
                    │  Risk Engine    │
                    │  (Python logic) │
                    └─────────────────┘
                            │
                            ▼
                    ┌─────────────────┐
                    │  Firewall Sim   │
                    │  (iptables cmd) │
                    └─────────────────┘
```

---

## 📂 Project Structure

```
firewall-workflow/
├── app.py                 # Main application (brain)
├── requirements.txt       # Python packages needed
├── README.md             # This file
├── firewall_workflow.db  # Database (created automatically)
├── templates/            # HTML pages
│   ├── base.html         # Layout template
│   ├── login.html        # Login page
│   ├── index.html        # Dashboard
│   ├── request_form.html # Submit request
│   ├── approve.html      # Approval queue
│   ├── audit.html        # Audit trail
│   └── request_detail.html # Single request view
└── static/               # CSS/JS files
    └── css/
```

---

## 🎓 For Your Course Presentation

### What to Say:
> *"Most organizations manage firewall changes through email and spreadsheets, which leads to misconfigurations — the #1 cause of network security incidents. Enterprise tools like AlgoSec solve this but cost thousands. My prototype demonstrates the same core security principles: risk-based approval workflows, separation of duties, immutable audit trails, and automated rollback — built with open-source tools that any organization can afford."*

### Demo Script (3 minutes):
1. **Login as john_doe** → Submit a HIGH RISK request (Port 22, 0.0.0.0/0)
2. **Show the Risk Score** → Explain how the engine calculated 9/10
3. **Login as security_sarah** → Show approval queue, approve the request
4. **Show Audit Trail** → Point out the immutable timeline
5. **Login as admin_mike** → Rollback the change, show the reverse command
6. **Explain the Four-Eyes Principle** → Try to approve your own request (it blocks you!)

---

## 🔮 Future Improvements

If you want to take this further:
- **Real Firewall Integration**: Connect to a Linux VM and actually run `iptables` commands
- **Email Notifications**: Send alerts when requests need approval
- **Rule Expiration**: Auto-expire rules after 30 days unless recertified (like AlgoSec)
- **Conflict Detection**: Warn if a new rule overlaps or contradicts an existing one
- **Multi-Factor Authentication**: Add OTP for approvers
- **REST API**: Allow other systems to submit requests programmatically

---

## 📜 License

Built for educational purposes. Feel free to extend and improve!

---

**Built with ❤️ for Network Security, Auditing and Monitoring coursework.**
