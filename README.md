# CyberIRS v2.0 — Cybersecurity Incident Response System

## Setup Instructions

### Step 1 — Install Dependencies
```
pip install flask flask-cors mysql-connector-python
```

### Step 2 — Setup Database
1. Open MySQL Workbench
2. Run `my_sql_file.sql` (creates all tables + sample data)
3. Then run `add_audit_log.sql` (adds Audit_Log table for new feature)

### Step 3 — Update Password
In `app.py`, change the DB password:
```python
"password": "your_mysql_password",
```

### Step 4 — Run the App
```
python app.py
```
Open: http://localhost:5000

---

## Login Credentials
| Username | Password    | Role    |
|----------|-------------|---------|
| admin    | admin123    | Admin   |
| analyst  | analyst123  | Analyst |

---

## New Features Added (v2.0)
- ✅ Login Page (session-based auth)
- ✅ Logout button
- ✅ Charts Page (Pie, Bar, Doughnut using Chart.js)
- ✅ Export CSV (download incidents)
- ✅ Audit Log (tracks all user actions)
- ✅ Email Alerts (configure in app.py EMAIL_CONFIG)
- ✅ Light professional theme (clean, authentic)
- ✅ User display in topbar

## Email Alerts (Optional)
In `app.py`, set `EMAIL_CONFIG`:
```python
EMAIL_CONFIG = {
    "enabled":   True,
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "username":  "your@gmail.com",
    "password":  "your_app_password",  # Gmail App Password
    "from":      "CyberIRS <your@gmail.com>",
    "to":        "admin@company.com",
}
```
