from flask import Flask, render_template, request
from url_analyzer import analyze_url
import sqlite3
from datetime import datetime

app = Flask(__name__)

DATABASE = "linklens.db"


# =========================================
# DATABASE INITIALIZATION
# =========================================

def init_db():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            risk TEXT NOT NULL,
            scan_time TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


# =========================================
# HOME PAGE
# =========================================

@app.route("/")
def home():

    return render_template("index.html")


# =========================================
# URL ANALYSIS
# =========================================

@app.route("/analyze", methods=["POST"])
def analyze():

    url = request.form.get("url", "").strip()

    if not url:

        return render_template(
            "index.html",
            error="Please enter a URL.",
            url=""
        )

    result = analyze_url(url)

    # Save scan result to SQLite
    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scan_history
        (url, score, risk, scan_time)
        VALUES (?, ?, ?, ?)
    """, (
        url,
        result["score"],
        result["risk"],
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()

    return render_template(
        "index.html",
        url=url,
        result=result
    )


# =========================================
# SCAN HISTORY
# =========================================

@app.route("/history")
def history():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, url, score, risk, scan_time
        FROM scan_history
        ORDER BY id DESC
    """)

    scans = cursor.fetchall()

    connection.close()

    return render_template(
        "history.html",
        scans=scans
    )


# =========================================
# DASHBOARD
# =========================================

@app.route("/dashboard")
def dashboard():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    # Total scans
    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
    """)

    total_scans = cursor.fetchone()[0]


    # Safe scans
    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE risk = 'SAFE'
    """)

    safe_scans = cursor.fetchone()[0]


    # Suspicious scans
    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE risk = 'SUSPICIOUS'
    """)

    suspicious_scans = cursor.fetchone()[0]


    # High-risk scans
    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE risk = 'HIGH RISK'
    """)

    high_risk_scans = cursor.fetchone()[0]


    # Calculate percentages
    if total_scans > 0:

        safe_percent = round(
            (safe_scans / total_scans) * 100
        )

        suspicious_percent = round(
            (suspicious_scans / total_scans) * 100
        )

        high_risk_percent = round(
            (high_risk_scans / total_scans) * 100
        )

    else:

        safe_percent = 0
        suspicious_percent = 0
        high_risk_percent = 0


    # Recent scans
    cursor.execute("""
        SELECT url, score, risk, scan_time
        FROM scan_history
        ORDER BY id DESC
        LIMIT 5
    """)

    recent_scans = cursor.fetchall()

    connection.close()


    return render_template(
        "dashboard.html",

        total_scans=total_scans,

        safe_scans=safe_scans,

        suspicious_scans=suspicious_scans,

        high_risk_scans=high_risk_scans,

        safe_percent=safe_percent,

        suspicious_percent=suspicious_percent,

        high_risk_percent=high_risk_percent,

        recent_scans=recent_scans
    )


# =========================================
# START FLASK APPLICATION
# =========================================

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )