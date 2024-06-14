import socket
import time
from zapv2 import ZAPv2
import mysql.connector

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

def get_cwe_description(cwe_id, cwe_descriptions):
    return cwe_descriptions.get(cwe_id, "Description not available")

def save_results_to_file(zap_results, output_file, cwe_descriptions):
    with open(output_file, "w") as f:
        f.write("OWASP ZAP Results:\n")
        if zap_results:
            for alert in zap_results:
                f.write(f"Alert: {alert.get('alert', 'N/A')}\n")
                f.write(f"Description: {alert.get('desc', 'N/A')}\n")
                f.write(f"Risk: {alert.get('risk', 'N/A')}\n")
                f.write(f"URL: {alert.get('url', 'N/A')}\n")
                f.write(f"Parameter: {alert.get('param', 'N/A')}\n")
                f.write(f"Attack: {alert.get('attack', 'N/A')}\n")
                f.write(f"Evidence: {alert.get('evidence', 'N/A')}\n")
                f.write(f"Solution: {alert.get('solution', 'N/A')}\n")
                f.write(f"Reference: {alert.get('reference', 'N/A')}\n")
                f.write(f"Other Info: {alert.get('other', 'N/A')}\n")
                if 'cweid' in alert and alert['cweid']:
                    cwe_id = f"CWE-{alert['cweid']}"
                    cwe_description = get_cwe_description(cwe_id, cwe_descriptions)
                    f.write(f"CWE ID: {cwe_id}\n")
                    f.write(f"CWE Description: {cwe_description}\n")
                f.write("\n")
        else:
            f.write("No OWASP ZAP results available.\n")

    print(f"OWASP ZAP scan results saved to {output_file}")

def save_results_to_db(zap_results, db_config, cwe_descriptions):
    conn = mysql.connector.connect(
        host=db_config['host'],
        user=db_config['user'],
        password=db_config['password'],
        database=db_config['database']
    )
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS zap_results (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        alert TEXT,
                        description TEXT,
                        risk TEXT,
                        url TEXT,
                        parameter TEXT,
                        attack TEXT,
                        cwe_id TEXT,
                        cwe_description TEXT,
                        scan_time DATETIME
                    )''')

    scan_time = time.strftime('%Y-%m-%d %H:%M:%S')

    for alert in zap_results:
        cwe_id = f"CWE-{alert['cweid']}" if 'cweid' in alert and alert['cweid'] else None
        cwe_description = get_cwe_description(cwe_id, cwe_descriptions) if cwe_id else None
        cursor.execute('''INSERT INTO zap_results (alert, description, risk, url, parameter, attack, cwe_id, cwe_description, scan_time) 
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                      (alert.get('alert', 'N/A'), alert.get('desc', 'N/A'), alert.get('risk', 'N/A'), alert.get('url', 'N/A'), alert.get('param', 'N/A'), alert.get('attack', 'N/A'), cwe_id, cwe_description, scan_time))

    conn.commit()
    cursor.close()
    conn.close()
    print("OWASP ZAP scan results saved to MariaDB database.")

def scan():
    target_url = input("Enter the target URL: ")
    target_ip = resolve_ip(target_url)

    if target_ip:
        api_key_file = "api_key.txt"
        cwe_file = "cwe_descriptions.txt"

        try:
            with open(api_key_file, "r") as f:
                api_key = f.read().strip()
        except FileNotFoundError:
            print(f"API key file {api_key_file} not found.")
            return

        cwe_descriptions = load_cwe_descriptions(cwe_file)
        
        timestamp = time.strftime("%Y%m%d%H%M%S")
        output_file = f"scan_results_{timestamp}.txt"

        db_config = {
            'host': 'localhost',
            'user': 'scan_user',
            'password': '#Scan2026',
            'database': 'scan_results'
        }

        zap_results = run_owasp_test(target_url, api_key)

        save_results_to_file(zap_results, output_file, cwe_descriptions)
        save_results_to_db(zap_results, db_config, cwe_descriptions)
        print("Scan completed successfully.")
    else:
        print("Failed to resolve IP address.")

if __name__ == "__main__":
    scan()
