"""
Cybersecurity IRS — Flask Backend (Enhanced)
Run:  python app.py
API available at http://localhost:5000
"""

from flask import Flask, jsonify, request, render_template, session, redirect, url_for, make_response
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error
from datetime import datetime, date
import decimal
import csv
import io
import smtplib
from email.mime.text import MIMEText
from functools import wraps

app = Flask(__name__)
app.secret_key = "cyberirs_secret_2024"
CORS(app)


DB_CONFIG = {
    "host":       "localhost",
    "port":       3306,
    "user":       "root",
    "password":   "teesha123",   
    "database":   "cybersecurity_irs",
    "charset":    "utf8mb4",
    "autocommit": False,
}


EMAIL_CONFIG = {
    "enabled":   False,         
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "username":  "your@gmail.com",
    "password":  "your_app_password",
    "from":      "CyberIRS Alerts <your@gmail.com>",
    "to":        "admin@company.com",
}


USERS = {
    "admin":    {"password": "admin123",  "role": "Admin"},
    "analyst":  {"password": "analyst123","role": "Analyst"},
}


def safe(obj):
    if isinstance(obj, (datetime, date)):
        return obj.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    return obj

def rows_to_list(rows):
    return [{k: safe(v) for k, v in row.items()} for row in rows]

def get_conn():
    return mysql.connector.connect(**DB_CONFIG)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


def log_action(action, details=""):
    try:
        conn   = get_conn()
        cursor = conn.cursor()
        user   = session.get("user", "system")
        ip     = request.remote_addr or "unknown"
        cursor.execute(
            "INSERT INTO Audit_Log (username, action, details, ip_address) VALUES (%s, %s, %s, %s)",
            (user, action, details, ip)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        try:
            cursor.close(); conn.close()
        except Exception:
            pass


def send_email_alert(subject, body):
    if not EMAIL_CONFIG["enabled"]:
        return
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"]    = EMAIL_CONFIG["from"]
        msg["To"]      = EMAIL_CONFIG["to"]
        with smtplib.SMTP(EMAIL_CONFIG["smtp_host"], EMAIL_CONFIG["smtp_port"]) as s:
            s.starttls()
            s.login(EMAIL_CONFIG["username"], EMAIL_CONFIG["password"])
            s.send_message(msg)
    except Exception:
        pass



@app.route("/login", methods=["GET"])
def login_page():
    if "user" in session:
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def do_login():
    data     = request.get_json()
    username = (data or {}).get("username", "").strip()
    password = (data or {}).get("password", "").strip()
    user     = USERS.get(username)
    if user and user["password"] == password:
        session["user"] = username
        session["role"] = user["role"]
        log_action("LOGIN", f"User {username} logged in")
        return jsonify({"success": True, "role": user["role"]})
    return jsonify({"success": False, "error": "Invalid username or password"}), 401

@app.route("/logout")
def logout():
    user = session.get("user", "unknown")
    log_action("LOGOUT", f"User {user} logged out")
    session.clear()
    return redirect(url_for("login_page"))

@app.route("/api/me")
def me():
    if "user" in session:
        return jsonify({"success": True, "user": session["user"], "role": session["role"]})
    return jsonify({"success": False}), 401


@app.route("/")
@login_required
def index():
    return render_template("index.html")




@app.route("/api/incidents", methods=["GET"])
@login_required
def get_incidents():
    status    = request.args.get("status")
    min_score = int(request.args.get("min_score", 0))
    sql = """
        SELECT i.incident_id, i.detected_at, i.status, i.threat_score,
               i.attacker_ip, i.description, i.resolved_at,
               sys.system_name, at.attack_name, at.severity_level,
               rt.team_name
        FROM   Incidents i
        JOIN   Systems      sys ON i.system_id      = sys.system_id
        JOIN   Attack_Types at  ON i.attack_type_id = at.attack_type_id
        LEFT JOIN Response_Teams rt ON i.team_id    = rt.team_id
        WHERE  i.threat_score >= %s
    """
    params = [min_score]
    if status:
        sql += " AND i.status = %s"
        params.append(status)
    sql += " ORDER BY i.threat_score DESC, i.detected_at DESC"
    try:
        conn   = get_conn()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql, params)
        rows = rows_to_list(cursor.fetchall())
        return jsonify({"success": True, "data": rows})
    except Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()


@app.route("/api/incidents", methods=["POST"])
@login_required
def add_incident():
    d = request.get_json()
    required = ["system_id", "attack_type_id", "attacker_ip", "threat_score", "description"]
    for field in required:
        if field not in d:
            return jsonify({"success": False, "error": f"Missing field: {field}"}), 400
    sql = """
        INSERT INTO Incidents
            (system_id, attack_type_id, attacker_ip, threat_score, status, description)
        VALUES (%s, %s, %s, %s, %s, %s)
    """
    try:
        conn   = get_conn()
        cursor = conn.cursor()
        cursor.execute(sql, (
            d["system_id"], d["attack_type_id"], d["attacker_ip"],
            d["threat_score"], d.get("status", "Open"), d["description"]
        ))
        conn.commit()
        new_id    = cursor.lastrowid
        triggered = int(d["threat_score"]) >= 80
        log_action("ADD_INCIDENT", f"Incident #{new_id} added from IP {d['attacker_ip']}")
        if triggered:
            send_email_alert(
                f"[CyberIRS] CRITICAL Incident #{new_id}",
                f"Critical threat detected!\nIP: {d['attacker_ip']}\nScore: {d['threat_score']}\nDesc: {d['description']}"
            )
        return jsonify({"success": True, "incident_id": new_id, "alert_triggered": triggered})
    except Error as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()


@app.route("/api/incidents/<int:incident_id>", methods=["PATCH"])
@login_required
def update_incident(incident_id):
    d      = request.get_json()
    fields = {k: v for k, v in d.items() if k in ["status", "threat_score", "description", "resolved_at", "team_id"]}
    if not fields:
        return jsonify({"success": False, "error": "No valid fields to update"}), 400
    set_clause = ", ".join(f"{k} = %s" for k in fields)
    values     = list(fields.values()) + [incident_id]
    try:
        conn   = get_conn()
        cursor = conn.cursor()
        cursor.execute(f"UPDATE Incidents SET {set_clause} WHERE incident_id = %s", values)
        conn.commit()
        log_action("EDIT_INCIDENT", f"Incident #{incident_id} updated: {fields}")
        return jsonify({"success": True, "updated": cursor.rowcount})
    except Error as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()


@app.route("/api/incidents/<int:incident_id>", methods=["DELETE"])
@login_required
def delete_incident(incident_id):
    try:
        conn   = get_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Incidents WHERE incident_id = %s", [incident_id])
        conn.commit()
        log_action("DELETE_INCIDENT", f"Incident #{incident_id} deleted")
        return jsonify({"success": True, "deleted": cursor.rowcount})
    except Error as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()


@app.route("/api/dashboard", methods=["GET"])
@login_required
def get_dashboard():
    urgent_only = request.args.get("urgent_only", "false").lower() == "true"
    sql = "SELECT * FROM vw_threat_dashboard"
    if urgent_only:
        sql += " WHERE priority_flag = 'URGENT'"
    sql += " ORDER BY threat_score DESC"
    try:
        conn   = get_conn()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql)
        return jsonify({"success": True, "data": rows_to_list(cursor.fetchall())})
    except Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()


@app.route("/api/stats", methods=["GET"])
@login_required
def get_stats():
    try:
        conn   = get_conn()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT
                COUNT(*)                                   AS total,
                SUM(status IN ('Open','In Progress'))      AS open_count,
                ROUND(AVG(threat_score), 1)                AS avg_score,
                SUM(threat_score >= 80)                    AS critical_count
            FROM Incidents
        """)
        stats = rows_to_list(cursor.fetchall())[0]
        cursor.execute(
            "SELECT COUNT(*) AS unacked FROM Alerts WHERE is_acknowledged=0 AND severity='Critical'"
        )
        stats["unacked_alerts"] = cursor.fetchone()["unacked"]
        return jsonify({"success": True, "data": stats})
    except Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()



@app.route("/api/charts/attacks-by-type", methods=["GET"])
@login_required
def chart_attacks_by_type():
    try:
        conn   = get_conn()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT at.attack_name, COUNT(*) AS count
            FROM Incidents i
            JOIN Attack_Types at ON i.attack_type_id = at.attack_type_id
            GROUP BY at.attack_name
            ORDER BY count DESC
        """)
        return jsonify({"success": True, "data": rows_to_list(cursor.fetchall())})
    except Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()


@app.route("/api/charts/incidents-by-day", methods=["GET"])
@login_required
def chart_incidents_by_day():
    try:
        conn   = get_conn()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT DATE(detected_at) AS day, COUNT(*) AS count
            FROM Incidents
            GROUP BY DATE(detected_at)
            ORDER BY day ASC
            LIMIT 14
        """)
        return jsonify({"success": True, "data": rows_to_list(cursor.fetchall())})
    except Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()


@app.route("/api/charts/status-breakdown", methods=["GET"])
@login_required
def chart_status_breakdown():
    try:
        conn   = get_conn()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT status, COUNT(*) AS count
            FROM Incidents
            GROUP BY status
        """)
        return jsonify({"success": True, "data": rows_to_list(cursor.fetchall())})
    except Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()



@app.route("/api/export/incidents", methods=["GET"])
@login_required
def export_incidents_csv():
    try:
        conn   = get_conn()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT i.incident_id, i.detected_at, i.status, i.threat_score,
                   i.attacker_ip, i.description, i.resolved_at,
                   sys.system_name, at.attack_name, at.severity_level, rt.team_name
            FROM Incidents i
            JOIN Systems sys ON i.system_id = sys.system_id
            JOIN Attack_Types at ON i.attack_type_id = at.attack_type_id
            LEFT JOIN Response_Teams rt ON i.team_id = rt.team_id
            ORDER BY i.threat_score DESC
        """)
        rows = rows_to_list(cursor.fetchall())
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=rows[0].keys() if rows else [])
        writer.writeheader()
        writer.writerows(rows)
        log_action("EXPORT_CSV", "Incidents exported to CSV")
        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=incidents_export.csv"
        response.headers["Content-Type"] = "text/csv"
        return response
    except Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()




@app.route("/api/alerts", methods=["GET"])
@login_required
def get_alerts():
    sql = """
        SELECT a.alert_id, a.created_at, a.alert_type, a.severity,
               a.message, a.is_acknowledged,
               i.attacker_ip, i.threat_score, sys.system_name
        FROM   Alerts a
        JOIN   Incidents i   ON a.incident_id = i.incident_id
        JOIN   Systems   sys ON i.system_id   = sys.system_id
        WHERE  a.is_acknowledged = 0 AND a.severity = 'Critical'
        ORDER  BY a.created_at DESC
    """
    try:
        conn   = get_conn()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql)
        return jsonify({"success": True, "data": rows_to_list(cursor.fetchall())})
    except Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()


@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["PATCH"])
@login_required
def acknowledge_alert(alert_id):
    try:
        conn   = get_conn()
        cursor = conn.cursor()
        cursor.execute("UPDATE Alerts SET is_acknowledged = 1 WHERE alert_id = %s", [alert_id])
        conn.commit()
        log_action("ACK_ALERT", f"Alert #{alert_id} acknowledged")
        return jsonify({"success": True, "acknowledged": cursor.rowcount > 0})
    except Error as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()




@app.route("/api/response-report", methods=["GET"])
@login_required
def response_report():
    team_id = request.args.get("team_id")
    team_id = int(team_id) if team_id else None
    try:
        conn   = get_conn()
        cursor = conn.cursor(dictionary=True)
        cursor.callproc("sp_response_time_report", [team_id])
        rows = []
        for rs in cursor.stored_results():
            rows.extend(rows_to_list(rs.fetchall()))
        return jsonify({"success": True, "data": rows})
    except Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()




@app.route("/api/repeat-attackers", methods=["GET"])
@login_required
def repeat_attackers():
    threshold = int(request.args.get("threshold", 1))
    sql = """
        SELECT i.attacker_ip,
               COUNT(*)                                              AS total_attacks,
               GROUP_CONCAT(DISTINCT at.attack_name
                            ORDER BY at.attack_name SEPARATOR ' | ') AS attack_types_used,
               MAX(i.threat_score)                                   AS max_threat_score,
               MIN(i.detected_at)                                    AS first_seen,
               MAX(i.detected_at)                                    AS last_seen,
               SUM(CASE WHEN i.status IN ('Open','In Progress')
                        THEN 1 ELSE 0 END)                           AS open_incidents
        FROM   Incidents i
        JOIN   Attack_Types at ON i.attack_type_id = at.attack_type_id
        GROUP  BY i.attacker_ip
        HAVING COUNT(*) > %s
        ORDER  BY total_attacks DESC
    """
    try:
        conn   = get_conn()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql, [threshold])
        return jsonify({"success": True, "data": rows_to_list(cursor.fetchall())})
    except Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()



@app.route("/api/audit-log", methods=["GET"])
@login_required
def get_audit_log():
    try:
        conn   = get_conn()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT log_id, username, action, details, ip_address, created_at
            FROM Audit_Log
            ORDER BY created_at DESC
            LIMIT 100
        """)
        return jsonify({"success": True, "data": rows_to_list(cursor.fetchall())})
    except Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()




@app.route("/api/systems", methods=["GET"])
@login_required
def get_systems():
    try:
        conn   = get_conn()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM Systems ORDER BY system_name")
        return jsonify({"success": True, "data": rows_to_list(cursor.fetchall())})
    except Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()


@app.route("/api/attack-types", methods=["GET"])
@login_required
def get_attack_types():
    try:
        conn   = get_conn()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM Attack_Types ORDER BY attack_name")
        return jsonify({"success": True, "data": rows_to_list(cursor.fetchall())})
    except Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()


@app.route("/api/teams", methods=["GET"])
@login_required
def get_teams():
    try:
        conn   = get_conn()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM Response_Teams ORDER BY team_name")
        return jsonify({"success": True, "data": rows_to_list(cursor.fetchall())})
    except Error as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close(); conn.close()



if __name__ == "__main__":
    print("\n" + "="*55)
    print("  Cybersecurity IRS — Flask Server Starting")
    print("  Open: http://localhost:5000")
    print("="*55 + "\n")
    app.run(debug=True, port=5000)
