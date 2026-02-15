<h1 align="center">
  <br>
  <a href="https://github.com/vibebhavv/Spinex"><img src="https://ibb.co/M5QQ53jF" alt="Spinex"></a>
  <br>
  Spinex
  <br>
</h1>
A Modular Adversary Simulation & Phishing Framework

SpineX Phish is a high-performance, template-driven framework designed for security researchers to conduct end-to-end phishing simulations. By decoupling the dashboard from the exfiltration server, it provides a stable environment for credential harvesting and target analytics.

### 🎯 Project Scope
This tool automates the three pillars of a modern phishing operation:

- Delivery: SMTP-based email spoofing with dynamic placeholder injection and device-specific login alerts.
- Hosting: A dual-server architecture using Flask to handle dynamic POST requests and credential storage.
- Exfiltration: A centralized Streamlit dashboard to monitor live sessions, manage tunnels, and analyze captured data.

### 🚀 Key Features
- Multi-Vector Tunneling: Integrated support for Ngrok, Cloudflare, and SSH (Localhost.run) with real-time PID tracking.
- Dynamic Flask Backend: A dedicated data receiver (server.py) that handles POST methods, preventing the "501 Unsupported Method" errors common in static servers.
- Precision Kill-Switch: Logic to terminate phish servers and tunnels without affecting the main Streamlit dashboard.
- Advanced Fingerprinting: Captures User-Agent, IP address, and timestamps, organized by the specific target username provided during the campaign.
- Agnostic Template Engine: Easily swap templates for Instagram, LinkedIn, or Corporate SSO by modifying the assets/ directory.


## 📂 Directory Structure
```
├── assets/
│   ├── mail_templates/    # HTML files for emails (IG, Google, etc.)
│   └── phish_temp/        # The actual fake login pages (index.html)
├── app.py                 # Main Streamlit interface (Admin Panel)
├── server.py              # Flask Backend (Data Receiver & File Server)
├── victims.json           # Live log of captured credentials
└── .streamlit/secrets.toml # SMTP & Email configuration
```
## 🛠️ Setup & Usage
Requirements
- Python 3.9+
- pipx install -r requirements.txt

SMTP Credentials (e.g., Gmail App Password)

Configuration
SMTP: Place your credentials in `.streamlit/secrets.toml`.

Server: Ensure `server.py` is in the root directory. It is called dynamically by the dashboard.

Tunneling: If using Ngrok, ensure your auth token is configured via CLI (`ngrok config add-authtoken <token>`).

### 📊 Deployment Workflow
- Craft: Use the Email Spoofer tab to set target parameters (Username, Device, etc.).
- Deploy: In the Phish Template tab, select a port (e.g., 8778) and start the server.
- Tunnel: Activate your preferred tunnel provider to generate a public URL.
- Launch: Send the email via the dashboard. The link will automatically include your active tunnel URL.

### 🛡️ Session Management
SpineX uses PID isolation. You can start and stop the phishing server or the public tunnel at any time using the "Kill All Sessions" button. This ensures that system resources are cleaned up properly without crashing the dashboard.

### 💡 Future Advancement
- Cookie Capturing
- 2FA bypass
- More templates

# ⚖️ Disclaimer
This software is provided for educational purposes and authorized penetration testing only. Unauthorized use of this tool against targets without prior written consent is illegal. The creator of SPINEX assumes no responsibility for any misuse or damage caused by this application.
