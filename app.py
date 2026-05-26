from flask import Flask, jsonify, render_template
import sqlite3
import requests

app = Flask(__name__)

DATABASE = "threats.db"


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        type TEXT,
        severity TEXT,
        description TEXT
    )
    """)

    conn.commit()

    cursor.execute("SELECT COUNT(*) FROM threats")
    count = cursor.fetchone()[0]

    if count == 0:
        sample_data = [
            ("Emotet", "Banking Trojan", "High",
             "Credential theft and banking malware."),

            ("WannaCry", "Ransomware", "Critical",
             "Global ransomware outbreak using SMB exploit."),

            ("Mirai", "Botnet", "Medium",
             "IoT botnet targeting insecure devices.")
        ]

        cursor.executemany("""
        INSERT INTO threats
        (name, type, severity, description)
        VALUES (?, ?, ?, ?)
        """, sample_data)

        conn.commit()

    conn.close()


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/threats")
def get_threats():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id, name, type, severity, description
    FROM threats
    """)

    rows = cursor.fetchall()

    conn.close()

    threats = []

    for row in rows:
        threats.append({
            "id": row[0],
            "name": row[1],
            "type": row[2],
            "severity": row[3],
            "description": row[4]
        })

    return jsonify(threats)

@app.route("/api/cves")
def get_cves():

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5"

    try:
        response = requests.get(url, timeout=10)

        data = response.json()

        vulnerabilities = []

        for item in data.get("vulnerabilities", []):

            cve = item.get("cve", {})

            cve_id = cve.get("id", "Unknown")

            descriptions = cve.get("descriptions", [])

            description = "No description"

            metrics = cve.get("metrics", {})

            cvss_score = "N/A"
            severity = "Unknown"

            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", "N/A")
                severity = cvss_data.get("baseSeverity", "Unknown")

            elif "cvssMetricV30" in metrics:
                  cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                  cvss_score = cvss_data.get("baseScore", "N/A")
                  severity = cvss_data.get("baseSeverity", "Unknown")

            elif "cvssMetricV2" in metrics:
                  cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                  cvss_score = cvss_data.get("baseScore", "N/A")
                  severity = metrics["cvssMetricV2"][0].get("baseSeverity", "Unknown")

            if descriptions:
                description = descriptions[0].get("value", "No description")

            vulnerabilities.append({
                "id": cve_id,
                "description": description,
                "cvss": cvss_score,
                "severity": severity
            })

        return jsonify(vulnerabilities)

    except Exception as e:
        return jsonify({
            "error": str(e)
        })

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
