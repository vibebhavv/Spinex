"""
proxy_page.py — Spinex Proxy Launcher Page

Start/stop mitmdump, run pre-flight checks, and tail the live log
all from the Streamlit dashboard.
"""

import streamlit as st
import os
import sys
import time

_AITM_DIR = os.path.dirname(os.path.abspath(__file__))
if _AITM_DIR not in sys.path:
    sys.path.insert(0, _AITM_DIR)
import config_manager  as cm
import proxy_launcher  as pl

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;700;800&display=swap');

:root {
    --bg:      #0a0a0f; --surface: #111118; --border: #1e1e2e;
    --accent:  #00ff9d; --accent2: #ff3c6e; --accent3: #7c5cff;
    --text:    #e2e2f0; --muted:   #6b6b8a;
    --ok:      #00ff9d; --warn:    #ffcc00; --fail:   #ff3c6e;
}
html, body, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
    background: var(--bg) !important; color: var(--text) !important;
}
[data-testid="stSidebar"] { background: var(--surface) !important; }
h1,h2,h3 { font-family:'Syne',sans-serif !important; font-weight:800 !important; letter-spacing:-0.03em; }

/* Status pill */
.status-pill {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 6px 18px; border-radius: 100px;
    font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; font-weight: 700;
    letter-spacing: 0.08em;
}
.status-running { background:#00ff9d18; color:var(--ok);  border:1px solid #00ff9d55; }
.status-stopped { background:#ff3c6e18; color:var(--fail); border:1px solid #ff3c6e55; }
.status-dot { width:8px; height:8px; border-radius:50%; animation: pulse 1.4s infinite; }
.status-dot-ok   { background: var(--ok); }
.status-dot-fail { background: var(--fail); animation: none; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }

/* Stat boxes */
.stat-row { display:flex; gap:12px; margin-bottom:1rem; }
.stat-box {
    flex:1; background:var(--surface); border:1px solid var(--border);
    border-radius:8px; padding:0.9rem 1rem;
}
.stat-label { font-size:0.68rem; font-weight:700; letter-spacing:0.15em;
              text-transform:uppercase; color:var(--muted); margin-bottom:4px; }
.stat-value { font-family:'JetBrains Mono',monospace; font-size:1.15rem;
              font-weight:700; color:var(--text); }

/* Pre-flight rows */
.pf-row { display:flex; align-items:center; gap:10px; padding:5px 0;
          font-family:'JetBrains Mono',monospace; font-size:0.8rem;
          border-bottom:1px solid #1a1a28; }
.pf-icon { width:18px; text-align:center; }
.pf-text { flex:1; }
.pf-ok   { color:var(--ok); }
.pf-warn { color:var(--warn); }
.pf-fail { color:var(--fail); }

/* Log terminal */
.log-terminal {
    background: #070710; border: 1px solid var(--border); border-radius:6px;
    padding: 1rem; height: 320px; overflow-y: auto;
    font-family: 'JetBrains Mono', monospace; font-size: 0.78rem;
    line-height: 1.6; color: #a0a0c0;
    white-space: pre-wrap; word-break: break-all;
}
.log-line-accent { color: var(--accent); }
.log-line-warn   { color: var(--warn); }
.log-line-fail   { color: var(--fail); }

/* Domain map mini table */
.dm-mini { width:100%; border-collapse:collapse;
           font-family:'JetBrains Mono',monospace; font-size:0.78rem; }
.dm-mini td { padding:4px 8px; border-bottom:1px solid #1a1a28; }
.dm-mini td.real  { color:var(--muted); }
.dm-mini td.arrow { color:var(--accent3); }
.dm-mini td.proxy { color:var(--accent); }

.accent-line { width:40px; height:3px; background:var(--accent); border-radius:2px; margin-bottom:0.5rem; }
</style>
"""


def _pf_row(icon: str, text: str, kind: str) -> str:
    return (
        f'<div class="pf-row">'
        f'<span class="pf-icon pf-{kind}">{icon}</span>'
        f'<span class="pf-text pf-{kind}">{text}</span>'
        f'</div>'
    )


def _colorise_log_line(line: str) -> str:
    """Wrap a log line in a colour span based on content keywords."""
    l = line.lower()
    if any(k in l for k in ("error", "fail", "exception", "traceback")):
        cls = "log-line-fail"
    elif any(k in l for k in ("warn", "warning")):
        cls = "log-line-warn"
    elif any(k in l for k in ("started", "captured", "session", "cookie", "cred")):
        cls = "log-line-accent"
    else:
        return line
    return f'<span class="{cls}">{line}</span>'


def render() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)
    st.markdown('<div class="accent-line"></div>', unsafe_allow_html=True)
    st.markdown("# ⚡ Proxy Launcher")
    st.markdown(
        '<p style="color:var(--muted);margin-top:-0.5rem;">'
        'Start and monitor the AiTM mitmproxy process.</p>',
        unsafe_allow_html=True,
    )

    cfg     = cm.load()
    running = pl.is_running()
    info    = pl.get_process_info() if running else {}

    col_status, col_btn = st.columns([3, 1])
    with col_status:
        if running:
            st.markdown(
                '<div class="status-pill status-running">'
                '<div class="status-dot status-dot-ok"></div>PROXY RUNNING'
                '</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="status-pill status-stopped">'
                '<div class="status-dot status-dot-fail"></div>PROXY STOPPED'
                '</div>',
                unsafe_allow_html=True,
            )

    with col_btn:
        if running:
            if st.button("🛑 Stop proxy", type="primary", use_container_width=True):
                ok, msg = pl.stop()
                st.toast(msg, icon="✅" if ok else "❌")
                time.sleep(1)
                st.rerun()
        else:
            if st.button("🚀 Start proxy", type="primary", use_container_width=True):
                preflight = pl.run_preflight(cfg)
                if not preflight.ok:
                    st.error("Pre-flight checks failed — fix the errors below before starting.")
                else:
                    with st.spinner("Launching mitmdump…"):
                        ok, msg = pl.start(cfg)
                    if ok:
                        st.success(msg)
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(msg)

    st.divider()

    if running and info:
        st.markdown(
            f'<div class="stat-row">'
            f'<div class="stat-box"><div class="stat-label">PID</div>'
            f'<div class="stat-value">{info.get("pid","—")}</div></div>'
            f'<div class="stat-box"><div class="stat-label">Uptime</div>'
            f'<div class="stat-value">{info.get("uptime","—")}</div></div>'
            f'<div class="stat-box"><div class="stat-label">CPU</div>'
            f'<div class="stat-value">{info.get("cpu","—")}</div></div>'
            f'<div class="stat-box"><div class="stat-label">Memory</div>'
            f'<div class="stat-value">{info.get("memory_mb","—")}</div></div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    col_pf, col_dm = st.columns(2)

    with col_pf:
        st.markdown("### 🔍 Pre-flight Checks")
        preflight = pl.run_preflight(cfg)
        html_rows = ""
        for item in preflight.passed:
            html_rows += _pf_row("✓", item, "ok")
        for item in preflight.warnings:
            html_rows += _pf_row("⚠", item, "warn")
        for item in preflight.errors:
            html_rows += _pf_row("✗", item, "fail")
        st.markdown(html_rows, unsafe_allow_html=True)

        if preflight.ok:
            st.markdown(
                '<p style="color:var(--ok);font-family:\'JetBrains Mono\',monospace;'
                'font-size:0.8rem;margin-top:0.5rem;">All checks passed — ready to launch.</p>',
                unsafe_allow_html=True,
            )

    with col_dm:
        st.markdown("### 🗺️ Active Domain Map")
        domain_map = cm.generate_domain_map(cfg)
        if domain_map:
            rows = "".join(
                f'<tr><td class="real">{real}</td>'
                f'<td class="arrow"> → </td>'
                f'<td class="proxy">{proxy}</td></tr>'
                for real, proxy in sorted(domain_map.items())
            )
            st.markdown(
                f'<table class="dm-mini"><tbody>{rows}</tbody></table>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<p style="color:var(--muted);font-size:0.85rem;">'
                'No domain mappings — configure in AiTM Config.</p>',
                unsafe_allow_html=True,
            )

        # mitmdump command preview
        cmd = cm.build_mitmproxy_cmd(cfg)
        with st.expander("View launch command"):
            st.code(" ".join(cmd), language="bash")

    st.divider()

    st.markdown("### 📟 Proxy Log")

    col_log1, col_log2 = st.columns([1, 5])
    with col_log1:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()
    with col_log2:
        if st.button("🗑️ Clear log", use_container_width=True):
            pl.clear_log()
            st.rerun()

    lines = pl.read_log(80)
    if lines:
        coloured = "\n".join(_colorise_log_line(l) for l in lines)
        st.markdown(
            f'<div class="log-terminal">{coloured}</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="log-terminal" style="color:var(--muted);">'
            'No log entries yet. Start the proxy to see output here.</div>',
            unsafe_allow_html=True,
        )

    # Auto-refresh every 5s when proxy is running
    if running:
        time.sleep(5)
        st.rerun()

if __name__ == "__main__":
    st.set_page_config(
        page_title="Spinex — Proxy Launcher",
        page_icon="⚡",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    render()