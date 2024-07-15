import mysql.connector
import matplotlib.pyplot as plt

def fetch_results_from_db(db_config, website):
    conn = mysql.connector.connect(
        host=db_config['host'],
        user=db_config['user'],
        password=db_config['password'],
        database=db_config['database']
    )
    cursor = conn.cursor(dictionary=True)

    query = '''SELECT risk, COUNT(*) as count
               FROM zap_results
               WHERE url LIKE %s
               GROUP BY risk'''
    cursor.execute(query, (f"%{website}%",))

    results = cursor.fetchall()

    cursor.close()
    conn.close()

    return results

def plot_risk_levels_pie(results, website):
    if not results:
        print(f"No results found for website: {website}")
        return

    labels = [result['risk'] for result in results]
    sizes = [result['count'] for result in results]

    plt.figure(figsize=(10, 6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title(f'OWASP ZAP Scan Results by Risk Level for {website}')
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.show()

# Database configuration
db_config = {
    'host': 'localhost',
    'user': 'scan_user',
    'password': '#Scan2026',
    'database': 'scan_results'
}

# Get website input from the user
website = input("Enter the website name to generate the chart: ")

# Fetch results from the database for the specified website
results = fetch_results_from_db(db_config, website)

# Plot the results as a pie chart for the specified website
plot_risk_levels_pie(results, website)

