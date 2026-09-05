import os
from flask import Flask, render_template, request, redirect, url_for, make_response, session
from dotenv import load_dotenv
from functools import wraps

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

app = Flask(__name__)
app.secret_key = "threatlens_secret_2024"

UPLOAD_FOLDER = "/tmp"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

from smart_parser import smart_parse_json
from smart_linux_parser import smart_parse_linux
from linux_detection import run_linux_detection
from detection import run_detection, get_summary
from database import register_user, verify_user

# ── In-memory alert storage ──────────────────────────────
current_alerts  = []
current_summary = {}


# ── Login required decorator ─────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ── Auth Routes ──────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user = verify_user(username, password)
        if user:
            session["username"] = user["username"]
            session["color"]    = "#3b82f6"
            return redirect(url_for("index"))
        else:
            error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    if "username" in session:
        return redirect(url_for("index"))

    error   = None
    success = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm  = request.form.get("confirm",  "").strip()

        if not username or not password:
            error = "Username and password are required."
        elif len(username) < 3:
            error = "Username must be at least 3 characters."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            role = "User"
            ok, message = register_user(username, password, role)
            if ok:
                success = "Account created! You can now log in."
            else:
                error = message

    return render_template("register.html", error=error, success=success)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Main Routes ──────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def index():
    global current_alerts, current_summary

    if request.method == "POST":
        uploaded_file = request.files.get("logfile")

        if not uploaded_file or uploaded_file.filename == "":
            return render_template("index.html", error="No file selected.",
                                   username=session.get("username"),
                                   role=session.get("role"),
                                   color=session.get("color"))

        filename = uploaded_file.filename
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        uploaded_file.save(filepath)

        if filename.endswith(".json"):
            logs, detected_format = smart_parse_json(filepath)
            current_alerts        = run_detection(logs)
        elif filename.endswith(".log") or filename.endswith(".txt"):
            logs, detected_format = smart_parse_linux(filepath)
            current_alerts        = run_linux_detection(logs)
        else:
            return render_template("index.html",
                                   error="Unsupported file. Upload .json or .log files.",
                                   username=session.get("username"),
                                   role=session.get("role"),
                                   color=session.get("color"))

        current_summary = get_summary(current_alerts)
        return redirect(url_for("dashboard"))

    return render_template("index.html", error=None,
                           username=session.get("username"),
                           role=session.get("role"),
                           color=session.get("color"))


@app.route("/dashboard")
def dashboard():
    severity_filter = request.args.get("severity", "All")
    search_query    = request.args.get("search", "").lower()
    filtered        = current_alerts

    if severity_filter != "All":
        filtered = [a for a in filtered if a["severity"] == severity_filter]

    if search_query:
        filtered = [a for a in filtered if
                    search_query in str(a["event_id"]) or
                    search_query in a["username"].lower() or
                    search_query in a["alert_name"].lower()]

    return render_template("dashboard.html",
                           alerts=filtered,
                           summary=current_summary,
                           severity_filter=severity_filter,
                           search_query=search_query,
                           username=session.get("username"),
                           role=session.get("role"),
                           color=session.get("color"))


@app.route("/lookup-page")

def lookup_page():
    return render_template("lookup.html",
                           username=session.get("username"),
                           role=session.get("role"),
                           color=session.get("color"))


@app.route("/lookup", methods=["POST"])

def lookup():
    from threat_intel import threat_lookup
    query = request.form.get("query", "").strip()
    if not query:
        return {"error": "Empty query."}, 400
    result = threat_lookup(query, VT_API_KEY)
    return result

@app.route("/filter-alerts")
def filter_alerts():
    severity_filter = request.args.get("severity", "All")
    search_query    = request.args.get("search", "").lower()
    filtered        = current_alerts

    if severity_filter != "All":
        filtered = [a for a in filtered if a["severity"] == severity_filter]

    if search_query:
        filtered = [a for a in filtered if
                    search_query in str(a["event_id"]) or
                    search_query in a["username"].lower() or
                    search_query in a["alert_name"].lower()]

    return {"alerts": filtered, "count": len(filtered)}
# ── PDF Report ───────────────────────────────────────────
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from io import BytesIO
from datetime import datetime


@app.route("/report")

def generate_report():
    if not current_alerts:
        return redirect(url_for("dashboard"))

    buffer = BytesIO()
    doc    = SimpleDocTemplate(buffer, pagesize=A4,
                               rightMargin=2*cm, leftMargin=2*cm,
                               topMargin=2*cm,   bottomMargin=2*cm)

    styles   = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle(
        "Title", parent=styles["Heading1"],
        fontSize=20, textColor=colors.HexColor("#c0392b"), spaceAfter=6)
    elements.append(Paragraph("ThreatLens — SOC Investigation Report", title_style))

    sub_style = ParagraphStyle(
        "Sub", parent=styles["Normal"],
        fontSize=10, textColor=colors.grey, spaceAfter=6)
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
        f"| Analyst: {session.get('username')} ({session.get('role')})",
        sub_style))
    elements.append(Spacer(1, 0.4*cm))

    section_style = ParagraphStyle(
        "Section", parent=styles["Heading2"],
        fontSize=13, textColor=colors.HexColor("#2c3e50"),
        spaceBefore=10, spaceAfter=8)
    elements.append(Paragraph("Executive Summary", section_style))

    summary_data = [
        ["Metric", "Count"],
        ["Total Alerts",    str(current_summary.get("total",    0))],
        ["Critical Alerts", str(current_summary.get("critical", 0))],
        ["High Alerts",     str(current_summary.get("high",     0))],
        ["Medium Alerts",   str(current_summary.get("medium",   0))],
        ["Low Alerts",      str(current_summary.get("low",      0))],
    ]

    summary_table = Table(summary_data, colWidths=[10*cm, 5*cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#f9f9f9"), colors.white]),
        ("GRID",           (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("FONTSIZE",       (0, 0), (-1, -1), 10),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.6*cm))
    elements.append(Paragraph("Detailed Alert Log", section_style))

    alert_header = ["#", "Severity", "Alert Name",
                    "Event ID", "Username", "MITRE ID", "Timestamp"]
    alert_rows   = [alert_header]

    for i, alert in enumerate(current_alerts, 1):
        alert_rows.append([
            str(i),
            alert["severity"],
            alert["alert_name"],
            str(alert["event_id"]),
            alert["username"],
            alert["mitre_id"],
            alert["timestamp"]
        ])

    col_widths  = [1*cm, 2.2*cm, 4.5*cm, 2*cm, 3*cm, 2.5*cm, 3.5*cm]
    alert_table = Table(alert_rows, colWidths=col_widths, repeatRows=1)

    def severity_color(sev):
        return {
            "Critical": colors.HexColor("#e74c3c"),
            "High":     colors.HexColor("#e67e22"),
            "Medium":   colors.HexColor("#3498db"),
            "Low":      colors.HexColor("#95a5a6"),
        }.get(sev, colors.grey)

    table_style = [
        ("BACKGROUND",     (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 8),
        ("GRID",           (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#f9f9f9"), colors.white]),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
        ("ALIGN",          (2, 1), (2, -1), "LEFT"),
    ]

    for i, alert in enumerate(current_alerts, 1):
        c = severity_color(alert["severity"])
        table_style.append(("TEXTCOLOR", (1, i), (1, i), c))
        table_style.append(("FONTNAME",  (1, i), (1, i), "Helvetica-Bold"))

    alert_table.setStyle(TableStyle(table_style))
    elements.append(alert_table)

    doc.build(elements)
    buffer.seek(0)

    response = make_response(buffer.read())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = \
        "attachment; filename=threatlens_report.pdf"
    return response


# ── Run ──────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=False)
