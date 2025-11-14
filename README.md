🔐 Credential Compromise Detection Lab — Splunk




🖥️ About

This project demonstrates detecting credential compromise using Splunk by correlating:

📧 Simulated phishing emails

🔑 Login events

🖥️ Process activity

Simulated datasets allow you to follow a full attack chain:

Phishing Click → Successful Login → Suspicious Process Execution

It’s ideal for portfolio demonstration, SOC workflow practice, and Splunk learning.

⚡ Features

🔗 Correlate multi-source logs (phish → login → process)

📊 Dashboard visualizing failed vs successful logins, top IPs, phishing correlations, and suspicious activity

🚨 Alerts for compromised accounts

📝 Ready-to-use SPL queries for threat hunting and investigation

📁 Repository Structure
splunk-credential-compromise-lab/
│
├── data/
│   ├── phish_emails.csv
│   ├── login_logs.csv
│   └── process_activity.csv
│
├── screenshots/
│   ├── dashboard-credential-compromise.png
│   ├── events-jessica.png
│   ├── alert-config.png
│   └── timeline.png (optional)
│
└── README.md

1️⃣ Lab Overview

This lab simulates a phishing → login → suspicious process attack chain. Objectives:

👤 Detect users who clicked phishing emails

🔍 Correlate login activity

⚡ Identify suspicious PowerShell executions

📊 Create dashboards and alerts

🗂️ Document findings for portfolio

2️⃣ Setup Instructions

💻 Install and open Splunk Free on a VM or local machine

📌 Create index: portifolio_lab2

📥 Ingest CSV files (phish_emails.csv, login_logs.csv, process_activity.csv)

✅ Validate ingestion:

index="portifolio_lab2" | stats count by sourcetype

3️⃣ Example SPL Queries
📧 A) Phishing Clicks
index="portifolio_lab2" sourcetype="phish_emails" clicked=true
| table email_id, recipient, timestamp, clicked
| sort - timestamp

👤 B) User Login Activity
index="portifolio_lab2" sourcetype="login_logs" username="jessicabraz"
| table event_id, timestamp, username, src_ip, status, device
| sort timestamp

🔗 C) Phishing → Login Correlation
index="portifolio_lab2" sourcetype="phish_emails"
| eval username = lower(replace(recipient, "@.*", ""))
| search clicked="true"
| join type=inner username [ search index="portifolio_lab2" sourcetype="login_logs" | eval username=lower(username) ]
| table email_id, recipient, username, timestamp, src_ip, status, device
| sort - timestamp

⚡ D) Suspicious PowerShell Activity
index="portifolio_lab2" sourcetype="process_activity"
| search process="powershell" cmdline="*-enc*"
| table proc_id, timestamp, host, username, process, cmdline
| sort - timestamp

🧩 E) Full Correlation (Phish → Login → Process)
index="portifolio_lab2" (sourcetype="phish_emails" OR sourcetype="login_logs" OR sourcetype="process_activity")
| eval username=coalesce(username, replace(recipient, "@.*$", ""))
| eval clicked_bool=if(clicked="true", 1, 0)
| transaction username maxspan=1h startswith=(sourcetype="phish_emails" AND clicked_bool=1) endswith=(sourcetype="process_activity")
| table username, duration, eventcount, _time, email_id, event_id, proc_id
| sort - _time

🚨 F) Failed Logins (Brute‑Force Indicator)
index="portifolio_lab2" sourcetype="login_logs" status="failed"
| stats count by username
| sort - count

🌐 G) Successful Logins from External IPs
index="portifolio_lab2" sourcetype="login_logs" status="success" NOT src_ip="192.168.*"
| table timestamp, username, src_ip, device
| sort - timestamp

4️⃣ Dashboards

📈 Failed vs Successful Logins: Timechart by hour

🌍 Top Source IPs: Bar chart by login attempts

🔗 Phishing → Login Correlation: Table with username, email_id, timestamp, src_ip, status

⚡ Suspicious Processes: Table showing PowerShell commands (*-enc*)

5️⃣ Alerts

🚨 Alert: User clicked phishing email and logged in successfully

⏱️ Trigger: Result count > 0

🗓️ Frequency: Every 15 minutes

📸 Action: Capture configuration screenshot (alert-config.png)

6️⃣ Screenshots
🖼️ File	📖 Description
dashboard-credential-compromise.png	Full dashboard
events-jessica.png	Timeline of phishing → login → process activity
alert-config.png	Alert configuration screen
timeline.png (optional)	Event sequence visualization
7️⃣ Skills Demonstrated

📥 Splunk data ingestion & field extraction

🧩 SPL queries & multi-source correlation

🔍 Threat hunting workflow

📊 Dashboard creation & alert configuration

👩‍💻 Simulated SOC investigation

👤 Author

Jessica Braz — Cybersecurity Student
🌏 Location: Australia 
GitHub: https://github.com/jessicabraz