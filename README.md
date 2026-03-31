🔐 Advanced Domain Security Analyzer

A professional-grade Python tool designed to perform comprehensive domain security assessments, analyzing email authentication, DNS configuration, infrastructure exposure, and domain integrity.

🚀 Project Overview

This project was built to simulate a real-world cybersecurity auditing tool, capable of identifying misconfigurations and potential vulnerabilities in domain setups.

It performs deep analysis across:

Email security (SPF, DMARC, DKIM)
DNS records and mail routing (MX)
Infrastructure exposure (CDN/WAF detection)
Domain integrity (WHOIS + DNSSEC)

👉 The output is a structured report that can be used for security audits, automation, or further analysis pipelines.

🧠 What makes this project valuable

This is not a basic script — it reflects how real security tools work in production environments.

✔ Detects misconfigurations that can lead to phishing or spoofing
✔ Evaluates domain exposure at infrastructure level
✔ Processes external data sources (DNS, WHOIS, RDAP)
✔ Generates structured, machine-readable results

📊 Example Usage
from diagnostico import diagnostico_Seguridad

report = diagnostico_Seguridad("example.com")

for item in report:
    print(item)
📄 Output & Reporting

The tool generates a structured report containing:

Category of analysis
Security status
Risk level (HIGH / MEDIUM / LOW)
Technical description
Risk score

👉 Designed to be easily extended into:

PDF reports
Dashboards
APIs
Security monitoring systems
🛠️ Technologies Used
Python 3
dnspython → DNS resolution
ipwhois → ASN & IP ownership analysis
python-whois → domain intelligence
ipaddress → IP validation & network handling
logging → monitoring and traceability
⚙️ Core Features
📧 Email Security Analysis
SPF validation and policy evaluation
DMARC enforcement analysis
DKIM detection using common selectors
🌐 Infrastructure Analysis
Detection of CDN/WAF protection
Identification of exposed servers
ASN and organization resolution
📬 Mail Configuration
MX record validation
Detection of insecure configurations (e.g., direct IP usage)
📄 Domain Intelligence
WHOIS parsing
Expiration checks
DNSSEC validation
🧩 Project Structure
diagnostico.py         # Core engine
Diagnostico_Ip.log     # Execution logs
README.md
💼 What this project demonstrates
Strong understanding of network protocols and DNS
Practical application of cybersecurity concepts
Ability to design modular and scalable Python systems
Experience working with real-world external data sources
Analytical thinking applied to security risk evaluation
🔥 Professional Impact

This project reflects the ability to:

Build tools beyond tutorials
Work with real infrastructure-level data
Think like a security engineer
Transform raw data into actionable insights
👨‍💻 Author

Cristian Chacon
Python Developer | Cybersecurity Enthusiast | Machine Learning
