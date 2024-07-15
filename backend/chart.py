import mysql.connector
import matplotlib.pyplot as plt

def fetch_results_from_db(db_config):
    conn = mysql.connector.connect(
        host=db_config['host'],
        user=db_config['user'],
        password=db_config['password'],
        database=db_config['database']
    )
    cursor = conn.cursor(dictionary=True)

    cursor.execute('''SELECT risk, COUNT(*) as count
                      FROM zap_results
                      GROUP BY risk''')

    results = cursor.fetchall()

    cursor.close()
    conn.close()

    return results

def plot_risk_levels_pie(results):
    labels = [result['risk'] for result in results]
    sizes = [result['count'] for result in results]

    plt.figure(figsize=(10, 6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title('OWASP ZAP Scan Results by Risk Level')
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.show()

# Database configuration
db_config = {
    'host': 'localhost',
    'user': 'scan_user',
    'password': '#Scan2026',
    'database': 'scan_results'
}

# Fetch results from the database
results = fetch_results_from_db(db_config)

# Plot the results as a pie chart
plot_risk_levels_pie(results)

