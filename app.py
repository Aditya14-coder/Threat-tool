import os
from flask import Flask, render_template, request, redirect, url_for, make_response
from log_parser import parse_log_file
from detection import run_detection, get_summary
from linux_detection import run_linux_detection
from smart_parser import smart_parse_json
from smart_linux_parser import smart_parse_linux
from threat_intel import threat_lookup
from dotenv import load_dotenv
from database import save_analysis, get_all_analyses, get_analysis_by_id, delete_analysis
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
app = Flask(__name__)

UPLOAD_FOLDER = "/tmp"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Store results in memory during the session
current_alerts = []
current_summary = {}

@app.route("/", methods=["GET", "POST"])
def index():
    global current_alerts, current_summary

    if request.method == "POST":
        uploaded_file = request.files.get("logfile")

        if not uploaded_file or uploaded_file.filename == "":
            return render_template("index.html", error="No file selected.")

        filename  = uploaded_file.filename
        filepath  = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        uploaded_file.save(filepath)

        # Route to correct parser based on file extension
        if filename.endswith(".json"):
            logs, detected_format = smart_parse_json(filepath)
            current_alerts        = run_detection(logs) 
        elif filename.endswith(".log") or filename.endswith(".txt"):
            logs, detected_format = smart_parse_linux(filepath)
            current_alerts        = run_linux_detection(logs)

        else:
            return render_template("index.html", error="Unsupported file type. Upload .json or .log files.")

        current_summary = get_summary(current_alerts)
        analysis_id = save_analysis(filename, current_alerts, current_summary)
        return redirect(url_for("dashboard"))

    return render_template("index.html", error=None)


@app.route("/dashboard")
def dashboard():
    severity_filter = request.args.get("severity", "All")
    search_query = request.args.get("search", "").lower()

    filtered_alerts = current_alerts

    if severity_filter != "All":
        filtered_alerts = [a for a in filtered_alerts if a["severity"] == severity_filter]

    if search_query:
        filtered_alerts = [a for a in filtered_alerts if
                           search_query in str(a["event_id"]) or
                           search_query in a["username"].lower() or
                           search_query in a["alert_name"].lower()]

    return render_template("dashboard.html",
                           alerts=filtered_alerts,
                           summary=current_summary,
                           severity_filter=severity_filter,
                           search_query=search_query)
@app.route("/lookup-page")
def lookup_page():
    return render_template("lookup.html")


@app.route("/lookup", methods=["POST"])
def lookup():
    query = request.form.get("query", "").strip()
    if not query:
        return {"error": "Empty query."}, 400

    result = threat_lookup(query, VT_API_KEY)
    return result

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from io import BytesIO
from datetime import datetime

@app.route("/history")
@login_required
def history():
    analyses = get_all_analyses()
    # Convert ObjectId to string for template
    for a in analyses:
        a["_id"] = str(a["_id"])
        a["uploaded_at"] = a["uploaded_at"].strftime("%Y-%m-%d %H:%M:%S")
    return render_template("history.html",
                           analyses=analyses,
                           username=session.get("username"),
                           role=session.get("role"),
                           color=session.get("color"))


@app.route("/history/<analysis_id>")
@login_required
def view_analysis(analysis_id):
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        return redirect(url_for("history"))

    alerts  = analysis.get("alerts", [])
    summary = analysis.get("summary", {})
    set_user_data(alerts, summary)
    return redirect(url_for("dashboard"))


@app.route("/history/delete/<analysis_id>")
@login_required
def delete_analysis_route(analysis_id):
    delete_analysis(analysis_id)
    return redirect(url_for("history"))

@app.route("/report")
def generate_report():
    if not current_alerts:
        return redirect(url_for("dashboard"))

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=2*cm, leftMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    elements = []

    # ── Title ──────────────────────────────────────────
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        fontSize=20,
        textColor=colors.HexColor("#c0392b"),
        spaceAfter=6
    )
    elements.append(Paragraph("ThreatTool — SOC Investigation Report", title_style))

    sub_style = ParagraphStyle(
        "Sub",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.grey,
        spaceAfter=20
    )
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", sub_style))

    # ── Summary Section ────────────────────────────────
    section_style = ParagraphStyle(
        "Section",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#2c3e50"),
        spaceBefore=10,
        spaceAfter=8
    )
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
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, 0), 11),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f9f9f9"), colors.white]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("FONTSIZE",    (0, 1), (-1, -1), 10),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 0.6*cm))

    # ── Alerts Table ───────────────────────────────────
    elements.append(Paragraph("Detailed Alert Log", section_style))

    alert_header = ["#", "Severity", "Alert Name", "Event ID", "Username", "MITRE ID", "Timestamp"]
    alert_rows = [alert_header]

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

    col_widths = [1*cm, 2.2*cm, 4.5*cm, 2*cm, 3*cm, 2.5*cm, 3.5*cm]
    alert_table = Table(alert_rows, colWidths=col_widths, repeatRows=1)

    def severity_color(severity):
        return {
            "Critical": colors.HexColor("#e74c3c"),
            "High":     colors.HexColor("#e67e22"),
            "Medium":   colors.HexColor("#3498db"),
            "Low":      colors.HexColor("#95a5a6"),
        }.get(severity, colors.grey)

    table_style = [
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f9f9f9"), colors.white]),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("ALIGN",         (2, 1), (2, -1), "LEFT"),
    ]

    for i, alert in enumerate(current_alerts, 1):
        c = severity_color(alert["severity"])
        table_style.append(("TEXTCOLOR", (1, i), (1, i), c))
        table_style.append(("FONTNAME",  (1, i), (1, i), "Helvetica-Bold"))

    alert_table.setStyle(TableStyle(table_style))
    elements.append(alert_table)

    # ── Build and Send ─────────────────────────────────
    doc.build(elements)
    buffer.seek(0)

    response = make_response(buffer.read())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=threattool_report.pdf"
    return response
if __name__ == "__main__":
    app.run(debug=False)
