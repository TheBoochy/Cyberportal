from flask import Flask, jsonify, render_template, request
from openai import OpenAI
from dotenv import load_dotenv

import sqlite3
import requests
import os
app = Flask(__name__)

DATABASE = "threats.db"


app = Flask(__name__)

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

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
@app.route("/api/ai", methods=["POST"])
def ai_analysis():
    data = request.get_json()
    prompt = data.get("prompt", "")

    cve_context = ""

    try:
        if "CVE-" in prompt.upper():
            cve_id = prompt.upper().split("CVE-")[1].split()[0]
            cve_id = "CVE-" + cve_id
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        else:
            keyword = prompt.strip().replace(" ", "%20")
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=5"

        nvd_response = requests.get(nvd_url, timeout=10)

        if nvd_response.status_code == 200:
            nvd_data = nvd_response.json()
            vulnerabilities = nvd_data.get("vulnerabilities", [])

            cve_ids = []

            for item in vulnerabilities:
                cve = item.get("cve", {})
                found_cve_id = cve.get("id", "Unknown")
                cve_ids.append(found_cve_id)

                descriptions = cve.get("descriptions", [])
                description = descriptions[0].get("value", "No description") if descriptions else "No description"

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

                cve_context += f"""
CVE: {found_cve_id}
CVSS: {cvss_score}
Severity: {severity}

Description:
{description}

"""

            if cve_ids:
                epss_url = "https://api.first.org/data/v1/epss?cve=" + ",".join(cve_ids)
                epss_response = requests.get(epss_url, timeout=10)

                if epss_response.status_code == 200:
                    epss_data = epss_response.json().get("data", [])

                    cve_context += "\nEPSS Exploit Probability Data:\n"

                    for epss_item in epss_data:
                        cve_context += f"""
CVE: {epss_item.get("cve")}
EPSS Score: {epss_item.get("epss")}
Percentile: {epss_item.get("percentile")}
"""

            kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            kev_response = requests.get(kev_url, timeout=10)

            if kev_response.status_code == 200:
                kev_data = kev_response.json().get("vulnerabilities", [])

                kev_matches = [
                    item for item in kev_data
                    if item.get("cveID") in cve_ids
                ]

                if kev_matches:
                    cve_context += "\nCISA KEV Known Exploited Matches:\n"

                    for kev in kev_matches:
                        cve_context += f"""
CVE: {kev.get("cveID")}
Vendor/Product: {kev.get("vendorProject")} / {kev.get("product")}
Known Ransomware Use: {kev.get("knownRansomwareCampaignUse")}
Required Action: {kev.get("requiredAction")}
Due Date: {kev.get("dueDate")}
"""

    except Exception:
        cve_context = "Unable to retrieve live CVE intelligence."

    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[
            {
                "role": "system",
                "content": "You are a cybersecurity threat intelligence analyst. Explain risk clearly, prioritize exploited vulnerabilities, and give practical defensive guidance. Do not provide exploit instructions."
            },
            {
                "role": "user",
                "content": f"""
User Question:
{prompt}

Live CVE / EPSS / CISA KEV Context:
{cve_context}

Provide a detailed cybersecurity analysis with:
1. Short summary
2. Most important CVEs
3. Exploitation risk
4. Whether any are known exploited
5. Recommended defensive actions
"""
            }
        ]
    )

    answer = response.choices[0].message.content

    return jsonify({
        "response": answer
    })

@app.route("/api/live-cves")
def live_cves():
    from datetime import datetime, timedelta, timezone

    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=7)

    start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start}"
        f"&pubEndDate={end}"
        "&resultsPerPage=10"
    )

    response = requests.get(url, timeout=10)

    if response.status_code != 200:
        return jsonify({
            "error": "Failed to fetch CVEs from NVD",
            "status_code": response.status_code,
            "details": response.text[:300]
        }), 500

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    results = []

    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "Unknown")
        published = cve.get("published", "Unknown")

        descriptions = cve.get("descriptions", [])
        description = descriptions[0].get("value", "No description available") if descriptions else "No description available"

        metrics = cve.get("metrics", {})
        severity = "UNKNOWN"
        cvss = "N/A"

        if "cvssMetricV31" in metrics:
            metric = metrics["cvssMetricV31"][0]
            severity = metric["cvssData"].get("baseSeverity", "UNKNOWN")
            cvss = metric["cvssData"].get("baseScore", "N/A")
        elif "cvssMetricV30" in metrics:
            metric = metrics["cvssMetricV30"][0]
            severity = metric["cvssData"].get("baseSeverity", "UNKNOWN")
            cvss = metric["cvssData"].get("baseScore", "N/A")
        elif "cvssMetricV2" in metrics:
            metric = metrics["cvssMetricV2"][0]
            severity = metric.get("baseSeverity", "UNKNOWN")
            cvss = metric["cvssData"].get("baseScore", "N/A")

        results.append({
            "id": cve_id,
            "published": published,
            "severity": severity,
            "cvss": cvss,
            "description": description
        })

    results.sort(key=lambda x: x["published"], reverse=True)

    return jsonify(results)

@app.route("/api/search-cves")
def search_cves():
    query = request.args.get("q", "")

    if not query:
        return jsonify([])

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=10"

    response = requests.get(url, timeout=10)
    data = response.json()

    results = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "Unknown")

        descriptions = cve.get("descriptions", [])
        description = descriptions[0].get("value", "No description") if descriptions else "No description"

        results.append({
            "id": cve_id,
            "description": description
        })

    return jsonify(results)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
