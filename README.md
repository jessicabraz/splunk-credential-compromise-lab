🧠 Project 2 — Credential Compromise Detection Lab (Splunk)

🎯 Objective

Simulate a security investigation using Splunk Free (Local) to detect credential compromise through phishing, suspicious logins, and process activity.
This lab demonstrates how to correlate multiple log sources, identify risky behaviors, and build dashboards and alerts for SOC analysis.

🧩 Dataset

Simulated CSV files created for this lab:

phish_emails.csv — simulated phishing emails (email_id, timestamp, recipient, subject, clicked)

login_logs.csv — login events (event_id, timestamp, username, src_ip, status, device)

process_activity.csv — process execution logs (proc_id, timestamp, host, username, process, cmdline)

All data is fictional and for educational purposes only.

⚙️ Steps Summary

Installed and opened Splunk Free locally on a VM or PC.

Created index: portifolio_lab2.

Ingested CSV files as data inputs with correct sourcetypes (phish_emails, login_logs, process_activity) and validated field extraction.

Ran example SPL queries:

All events:

index="portifolio_lab2"


Users who clicked phishing emails:

index="portifolio_lab2" sourcetype="phish_emails" clicked=true
| table email_id, recipient, timestamp, clicked


Login activity for user (example: jessicabraz):

index="portifolio_lab2" sourcetype="login_logs" username="jessicabraz"
| table event_id, timestamp, username, src_ip, status, device


Phishing → Login correlation:

index="portifolio_lab2" sourcetype="phish_emails"
| eval username = lower(replace(recipient, "@.*", ""))
| search clicked="true"
| join type=inner username [ search index="portifolio_lab2" sourcetype="login_logs" | eval username=lower(username) ]
| table email_id, recipient, username, timestamp, src_ip, status, device


Suspicious PowerShell activity:

index="portifolio_lab2" sourcetype="process_activity"
| search process="powershell" cmdline="*-enc*"
| table proc_id, timestamp, host, username, process, cmdline


Created Dashboard with panels for:

Failed vs Successful Logins (timechart)

Top 10 source IPs (bar chart)

Phishing → Login correlation (table)

Suspicious PowerShell processes (table)

Configured alerts:

User clicked phishing email → successful login (trigger if results > 0)

Multiple failed login attempts (≥5 in 10 minutes)

📊 Dashboard Examples

dashboard-credential-compromise.png — full dashboard overview

events-jessica.png — timeline of phishing → login → process activity

alert-config.png — alert configuration screenshot

 🔍Results

Identified users who clicked phishing emails and subsequently logged in successfully.

Correlated login events with suspicious PowerShell executions.

Visualized attack timelines and top source IPs.

Configured alerts for potentially compromised accounts.

💡 Key Takeaways

Learned multi-source correlation using SPL queries.

Gained experience creating dashboards and alerts in Splunk.

Practiced SOC workflow: detection → investigation → documentation.

Reinforced understanding of credential compromise and lateral movement techniques.

🚀 Next Steps

Ingest real-world log sources (network, Linux, cloud) for extended correlation.

Automate alert response with scripts or webhooks.

Simulate lateral movement and escalated attacks to enhance lab complexity.

🧰 Tools Used

Splunk Free (Local)

CSV simulated datasets

Markdown for documentation (GitHub)

👩‍💻 Author

Jessica Braz — Cybersecurity Student
Location: Australia
GitHub: https://github.com/jessicabraz
