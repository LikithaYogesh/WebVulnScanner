# Site Secure: Advanced Website Vulnerability Scanner

Site Secure is a robust, automated vulnerability scanner designed to identify security flaws in web applications. By augmenting the capabilities of OWASP ZAP with custom scripts, dashboards, and a full-stack reporting interface, this tool empowers developers and security teams to proactively assess and harden their web applications against the OWASP Top 10 vulnerabilities and beyond.

---

## Features

- **Automated Vulnerability Detection:** Detects a wide range of security flaws using OWASP ZAP spidering and active scanning.
- **Custom Scripts and Configurations:** Enhances ZAP scans with custom rules, tailored scripts, and configurable depth/scope.
- **OWASP Top 10 Focused:** Designed to specifically uncover the most critical web application security risks.
- **Interactive Web Dashboard:** Displays scan results, CWE links, and risk-level breakdowns with integrated graphs.
- **Detailed Reporting:** Includes Flask-based API to manage scans and results programmatically.
- **Modular Backend API:** Generate detailed scan results in HTML, JSON, or CSV format.
- **CWE Mapping:** Includes automatic mapping of vulnerabilities to CWE descriptions for educational and compliance reporting.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/site-secure.git
   cd site-secure
   
2. Install dependencies:

       pip install -r requirements.txt

3. Download and configure OWASP ZAP:

Download OWASP ZAP
Set up the ZAP API key in the environment variables:


     export ZAP_API_KEY="your_api_key"
     
4. Configure custom scripts and settings:

Place your custom scripts in the scripts/ folder.
Update config.yaml for advanced settings.

---

## Usage

1. Start OWASP ZAP:


       zap.sh -daemon -config api.key=your_api_key

2. Run the scanner:

 
       python site_secure.py --url https://targetwebsite.com

3. View the results:

Open the generated report in the reports/ directory.

---

## Configuration

Modify the config.yaml file to customize scanning options:

     target_url: https://example.com
     scan_depth: 3
     auth_required: false
     auth_details:
     username: your_username
     password: your_password
     report_format: html
---

## Contributing

We welcome contributions to improve Site Secure. To contribute:

1. Fork the repository.
2. Create a new branch:

        git checkout -b feature-name

3. Commit your changes:

       git commit -m "Add new feature"

4. Push your branch and create a pull request.

---

## Visualizations
The backend supports risk-based analysis through:

- **chart.py:** pie chart of risk severity across all scans

- **chartsite.py:** pie chart filtered by domain

These use matplotlib and run from the terminal.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

## Disclaimer

This tool is intended for ethical use only. Always obtain proper authorization before scanning any website or application. The developers are not responsible for misuse of this tool.




