"""
cert_manager.py — Spinex TLS Certificate Manager

Handles Let's Encrypt wildcard certificate lifecycle:
  - Fetch via certbot (DNS-01 challenge, multiple providers)
  - Check expiry and validity
  - Auto-renewal when < 30 days remaining
  - Combine cert + key into single PEM for mitmproxy
  - Write Cloudflare credentials file from config
"""

import os
import subprocess
import datetime
import json
import traceback
import ssl
import socket
import tempfile

import config_manager as cm

import sys as _sys
_AITM_DIR     = os.path.dirname(os.path.abspath(__file__))
BASE_DIR      = os.path.dirname(_AITM_DIR)
if _AITM_DIR not in _sys.path:
    _sys.path.insert(0, _AITM_DIR)

CREDS_DIR     = os.path.join(BASE_DIR, "creds")
COMBINED_CERT = os.path.join(CREDS_DIR, "combined-cert.pem")
CF_CREDS_FILE = os.path.join(CREDS_DIR, ".cloudflare.ini")  # auto-written, kept private

os.makedirs(CREDS_DIR, exist_ok=True)

DNS_PROVIDERS = {
    "cloudflare":    "Cloudflare",
    "route53":       "AWS Route53",
    "digitalocean":  "DigitalOcean",
    "namecheap":     "Namecheap (via acme.sh)",
    "manual":        "Manual (copy-paste TXT record)",
}

class CertStatus:
    def __init__(self):
        self.exists        = False
        self.valid         = False
        self.expiry        = None          # datetime
        self.days_left     = None          # int
        self.needs_renewal = False
        self.combined_ok   = False         # combined PEM for mitmproxy exists
        self.error         = None          # str if something went wrong

    def to_dict(self) -> dict:
        return {
            "exists":        self.exists,
            "valid":         self.valid,
            "expiry":        str(self.expiry) if self.expiry else None,
            "days_left":     self.days_left,
            "needs_renewal": self.needs_renewal,
            "combined_ok":   self.combined_ok,
            "error":         self.error,
        }


def get_cert_status(config: dict, renewal_threshold: int = 30) -> CertStatus:
    """
    Check the state of the TLS certificate for the configured domain.
    Reads the cert file directly to get the real expiry date.
    """
    status = CertStatus()
    cert_path, key_path = cm.get_cert_paths(config)

    # Check file existence
    if not (cert_path and key_path):
        status.error = "Cert/key paths not configured."
        return status

    if not os.path.exists(cert_path):
        status.error = f"Certificate not found at {cert_path}"
        return status

    if not os.path.exists(key_path):
        status.error = f"Private key not found at {key_path}"
        return status

    status.exists = True

    # Parse expiry from cert file using openssl
    try:
        result = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", cert_path],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            # Output: "notAfter=May 14 12:00:00 2026 GMT"
            raw = result.stdout.strip().replace("notAfter=", "")
            expiry = datetime.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
            status.expiry    = expiry
            status.days_left = (expiry - datetime.datetime.utcnow()).days
            status.valid     = status.days_left > 0
            status.needs_renewal = status.days_left < renewal_threshold
        else:
            status.error = f"openssl error: {result.stderr.strip()}"
    except FileNotFoundError:
        # openssl not in PATH — fall back to Python ssl module
        try:
            import ssl as _ssl
            cert_dict = _ssl._ssl._test_decode_cert(cert_path)  # type: ignore
            not_after = cert_dict.get("notAfter", "")
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            status.expiry    = expiry
            status.days_left = (expiry - datetime.datetime.utcnow()).days
            status.valid     = status.days_left > 0
            status.needs_renewal = status.days_left < renewal_threshold
        except Exception as e:
            status.error = f"Could not parse cert expiry: {e}"
    except Exception as e:
        status.error = str(e)

    # Check combined PEM for mitmproxy
    status.combined_ok = os.path.exists(COMBINED_CERT) and os.path.getsize(COMBINED_CERT) > 0

    return status

def build_combined_pem(config: dict) -> tuple[bool, str]:
    """
    Concatenate private key + full chain into one PEM file at COMBINED_CERT.
    mitmproxy's --certs flag requires this format.

    Returns (success: bool, message: str)
    """
    cert_path, key_path = cm.get_cert_paths(config)

    if not os.path.exists(cert_path):
        return False, f"Certificate not found: {cert_path}"
    if not os.path.exists(key_path):
        return False, f"Private key not found: {key_path}"

    try:
        with open(key_path,  "r") as kf: key_data  = kf.read()
        with open(cert_path, "r") as cf: cert_data = cf.read()

        combined = key_data.strip() + "\n" + cert_data.strip() + "\n"

        with open(COMBINED_CERT, "w") as out:
            out.write(combined)

        return True, f"Combined PEM written to {COMBINED_CERT}"
    except Exception as e:
        return False, f"Failed to build combined PEM: {e}"


def write_cloudflare_credentials(api_token: str) -> str:
    """
    Write the Cloudflare API token to the certbot credentials file.
    Returns the path to the file.
    """
    content = f"# Cloudflare API token — generated by Spinex\ndns_cloudflare_api_token = {api_token}\n"
    with open(CF_CREDS_FILE, "w") as f:
        f.write(content)
    # Restrict permissions (certbot requires 600 on Linux)
    try:
        os.chmod(CF_CREDS_FILE, 0o600)
    except Exception:
        pass
    return CF_CREDS_FILE

def _run_certbot(cmd: list[str], timeout: int = 120) -> tuple[bool, str]:
    """
    Run a certbot command and return (success, output).
    Captures both stdout and stderr.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout + "\n" + result.stderr
        return result.returncode == 0, output.strip()
    except subprocess.TimeoutExpired:
        return False, f"certbot timed out after {timeout}s"
    except FileNotFoundError:
        return False, "certbot not found. Install with: pip install certbot"
    except Exception as e:
        return False, str(e)


def fetch_cert(
    config: dict,
    dns_provider: str,
    api_token: str = "",
    propagation_seconds: int = 60,
) -> tuple[bool, str]:
    """
    Fetch a new wildcard TLS certificate via Let's Encrypt DNS-01 challenge.

    Supports:
        cloudflare   — uses certbot-dns-cloudflare plugin
        route53      — uses certbot-dns-route53 plugin (AWS credentials from env)
        digitalocean — uses certbot-dns-digitalocean plugin
        manual       — interactive: user manually adds DNS TXT record

    Returns (success: bool, output: str)
    """
    base  = config["domain"]["base"].strip()
    email = config["domain"]["acme_email"].strip()

    if not base or not email:
        return False, "Base domain and ACME email are required."

    # Common flags for all providers
    base_cmd = [
        "certbot", "certonly",
        "--non-interactive",
        "--agree-tos",
        "--email", email,
        "-d", base,
        "-d", f"*.{base}",
    ]

    if dns_provider == "cloudflare":
        if not api_token:
            return False, "Cloudflare API token is required."
        cf_creds = write_cloudflare_credentials(api_token)
        cmd = base_cmd + [
            "--dns-cloudflare",
            "--dns-cloudflare-credentials", cf_creds,
            "--dns-cloudflare-propagation-seconds", str(propagation_seconds),
        ]

    elif dns_provider == "route53":
        # Uses AWS credentials from environment (AWS_ACCESS_KEY_ID etc.)
        cmd = base_cmd + [
            "--dns-route53",
            "--dns-route53-propagation-seconds", str(propagation_seconds),
        ]

    elif dns_provider == "digitalocean":
        if not api_token:
            return False, "DigitalOcean API token is required."
        # Write DO credentials file
        do_creds = os.path.join(CREDS_DIR, ".digitalocean.ini")
        with open(do_creds, "w") as f:
            f.write(f"dns_digitalocean_token = {api_token}\n")
        try:
            os.chmod(do_creds, 0o600)
        except Exception:
            pass
        cmd = base_cmd + [
            "--dns-digitalocean",
            "--dns-digitalocean-credentials", do_creds,
            "--dns-digitalocean-propagation-seconds", str(propagation_seconds),
        ]

    elif dns_provider == "manual":
        # Manual mode is interactive — can't run non-interactively
        # Return the command for the user to run themselves
        manual_cmd = (
            f"certbot certonly --manual --preferred-challenges dns "
            f"--agree-tos --email {email} "
            f"-d {base} -d *.{base}"
        )
        return False, (
            f"Manual mode requires interactive input.\n"
            f"Run this command on your server and follow the prompts:\n\n"
            f"  {manual_cmd}"
        )

    else:
        return False, f"Unknown DNS provider: {dns_provider}"

    success, output = _run_certbot(cmd, timeout=180)

    if success:
        # Auto-build combined PEM after successful cert fetch
        ok, msg = build_combined_pem(config)
        if not ok:
            output += f"\n⚠️  Warning: {msg}"
        else:
            output += f"\n✅ {msg}"

    return success, output


def renew_cert(config: dict) -> tuple[bool, str]:
    """
    Run `certbot renew` for the configured domain.
    Only renews if the cert is within the renewal threshold.
    Rebuilds combined PEM on success.
    """
    base = config["domain"]["base"].strip()
    if not base:
        return False, "Base domain is required."

    cmd = [
        "certbot", "renew",
        "--cert-name", base,
        "--non-interactive",
        "--quiet",
    ]
    success, output = _run_certbot(cmd, timeout=180)

    if success:
        ok, msg = build_combined_pem(config)
        output += f"\n{'✅' if ok else '⚠️'} {msg}"

    return success, output


def check_and_auto_renew(config: dict, threshold_days: int = 30) -> tuple[bool, str]:
    """
    Check cert expiry and auto-renew if within threshold.
    Designed to be called on a schedule (e.g. daily cron / background thread).
    Returns (renewed: bool, message: str)
    """
    status = get_cert_status(config, renewal_threshold=threshold_days)

    if not status.exists:
        return False, "No certificate found — fetch one first."

    if not status.needs_renewal:
        return False, f"Cert is valid for {status.days_left} more days — no renewal needed."

    success, output = renew_cert(config)
    if success:
        return True, f"Renewed successfully.\n{output}"
    return False, f"Renewal failed:\n{output}"