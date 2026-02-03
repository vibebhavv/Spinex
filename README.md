# SpineX Phish
A Modular Adversary Simulation & Phishing Framework

SpineX Phish is a high-performance, template-driven framework designed for security researchers to conduct end-to-end phishing simulations. While it ships with Instagram-style templates, its core engine is built to simulate any authentication flow.

### 🎯 Project Scope

This tool automates the three pillars of a phishing operation:

- Delivery: SMTP-based email spoofing with dynamic placeholder injection.
- Hosting: Integrated instatunnel manager to expose local landing pages to the WAN.
- Exfiltration: A centralized dashboard to monitor "Captured" vs "Converted" targets.

### 🚀 Key Features
- Agnostic Template Engine: Easily add new targets (LinkedIn, Google, Corporate SSO) by dropping HTML files into the assets/ directory.
- Live Payload Preview: Side-by-side HTML editor and previewer to ensure your email looks perfect before "Launch."
- Logical Analytics: Real-time calculation of CTR (Click-Through Rate) and Conversion Success using local JSON state management.
- Device Fingerprinting: Captures User-Agent, IP address, and screen resolution to identify sandbox environments or security crawlers.

## 📂 Directory Structure
```
├── assets/
│   ├── mail_templates/    # HTML files for the emails (IG, Google, etc.)
│   ├── phish_temp/        # The actual fake login pages
│   └── spinex_logo.png    # Dashboard branding
├── victims.json           # Log of captured credentials
├── stats.json             # Counter for sent emails (logical tracking)
└── app.py                 # Main Streamlit interface
```

## 🛠️ Setup & Usage
Requirements
- Python 3.9+
- Node.js (for instatunnel)
- SMTP Credentials (e.g., Gmail App Password)

Configuration
- Place your SMTP credentials in ```.streamlit/secrets.toml```:
```
[email]
sender_email = "your-email@gmail.com"
app_password = "xxxx xxxx xxxx xxxx"
smtp_server = "smtp.gmail.com"
port = 587
```
### 📊 Conversion Funnel Logic
The dashboard doesn't just show numbers; it tracks the effectiveness of your campaign:

- Sent: Every time a campaign is launched, stats.json increments.

- Captured: Logged when a target visits the link (Fingerprinting).

- Converted: Logged when the target submits the password field.

# ⚖️ Disclaimer
This software is provided for educational purposes and authorized penetration testing only. The author is not responsible for any misuse or damage caused by this tool. Always obtain written consent before testing.
