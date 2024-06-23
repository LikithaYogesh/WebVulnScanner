import socket
import time
from zapv2 import ZAPv2
import mysql.connector
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Database configuration
db_config = {
    'host': 'localhost',
    'user': 'scan_user',
    'password': '#Scan2026',
    'database': 'scan_results'
}

# Load CWE descriptions
def load_cwe_descriptions(cwe_file):
    cwe_descriptions = {}
    try:
        with open(cwe_file, "r") as file:
            for line in file:
                if line.strip():  # Skip empty lines
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        cwe_id, description = parts
                        cwe_descriptions[cwe_id.strip()] = description.strip()
                    else:
                        print(f"Skipping improperly formatted line: {line.strip()}")
    except FileNotFoundError:
        print(f"File {cwe_file} not found.")
    return cwe_descriptions

cwe_descriptions = load_cwe_descriptions("cwe_descriptions.txt")

# Resolve IP address
def resolve_ip(target_url):
    try:
        hostname = target_url.split("//")[-1].split("/")[0]
        print(f"Resolving hostname: {hostname}")
        ip_address = socket.gethostbyname(hostname)
        print(f"Resolved IP address: {ip_address}")
        return ip_address
    except socket.gaierror as e:
        print(f"Failed to resolve IP address for {hostname}: {e}")
        return None

# Run OWASP ZAP scan
def run_owasp_test(target_url, api_key):
    zap = ZAPv2(apikey=api_key)
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    print('Spidering target {}'.format(target_url))
    try:
        scanID = zap.spider.scan(target_url)
        while int(zap.spider.status(scanID)) < 100:
            print('Spider progress %: {}'.format(zap.spider.status(scanID)))
            time.sleep(1)
        print('Spider has completed!')
        print('\n'.join(map(str, zap.spider.results(scanID))))
    except Exception as e:
        print(f"Error during OWASP ZAP spidering: {e}")
        return None

    print("Performing OWASP ZAP active scan...")
    try:
        scan_id = zap.ascan.scan(target_url)
        while int(zap.ascan.status(scan_id)) < 100:
            print(f"Scan progress: {zap.ascan.status(scan_id)}%")
            time.sleep(5)
        print("Retrieving OWASP ZAP scan results...")
        zap_results = zap.core.alerts(baseurl=target_url)
        return zap_results
    except Exception as e:
        print(f"Error during OWASP ZAP scan: {e}")
        return None

# Save results to database
def save_results_to_db(zap_results):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS zap_results (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        alert TEXT,
                        solution TEXT,
                        risk TEXT,
                        url TEXT,
                        parameter TEXT,
                        evidence TEXT,
                        cwe_id TEXT,
                        cwe_description TEXT,
                        scan_time DATETIME
                    )''')

    scan_time = time.strftime('%Y-%m-%d %H:%M:%S')

    for alert in zap_results:
        cwe_id = f"CWE-{alert['cweid']}" if 'cweid' in alert and alert['cweid'] else None
        cwe_description = get_cwe_description(cwe_id) if cwe_id else None
        cursor.execute('''INSERT INTO zap_results (alert, solution, risk, url, parameter, evidence, cwe_id, cwe_description, scan_time) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                    (alert.get('alert', 'N/A'), alert.get('solution', 'N/A'), alert.get('risk', 'N/A'), alert.get('url', 'N/A'), alert.get('param', 'N/A'), alert.get('evidence', 'N/A'), cwe_id, cwe_description, scan_time))

    conn.commit()
    cursor.close()
    conn.close()
    print("OWASP ZAP scan results saved to MariaDB database.")

# Retrieve CWE description
def get_cwe_description(cwe_id):
    return cwe_descriptions.get(cwe_id, "Description not available")

# Route to trigger scan
@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    target_url = data.get('target_url')
    
    if not target_url:
        return jsonify({"error": "Target URL is required"}), 400

    api_key_file = "api_key.txt"
    try:
        with open(api_key_file, "r") as f:
            api_key = f.read().strip()
    except FileNotFoundError:
        return jsonify({"error": f"API key file {api_key_file} not found"}), 500

    target_ip = resolve_ip(target_url)
    if not target_ip:
        return jsonify({"error": "Failed to resolve IP address"}), 400

    zap_results = run_owasp_test(target_url, api_key)
    if zap_results is not None:
        save_results_to_db(zap_results)
        return jsonify({"message": "Scan completed successfully"}), 200
    else:
        return jsonify({"error": "Scan failed"}), 500

# Route to fetch scan results
@app.route('/api/results', methods=['GET'])
def get_results():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM zap_results ORDER BY scan_time DESC")
    results = cursor.fetchall()

    cursor.close()
    conn.close()

    return jsonify(results), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

