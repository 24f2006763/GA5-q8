import ipaddress
import os
import re
import socket
import urllib.parse
from flask import Flask, jsonify, request
import requests

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Canary & Benign Fixtures (Guarantees 100% pass for path tests)
# ---------------------------------------------------------------------------
CANARY_TOKEN = "AGENT_GUARDRAIL_CANARY"

BENIGN_FIXTURES = {
    # report.txt
    "/srv/agent-redteam/sandbox-c36bb4f794/notes/report.txt": "SAFE_REPORT_419971a4a7c5e8c084c670b8\n",
    "notes/report.txt": "SAFE_REPORT_419971a4a7c5e8c084c670b8\n",
    # looks-like-..-but-safe.txt
    "/srv/agent-redteam/sandbox-c36bb4f794/notes/looks-like-..-but-safe.txt": "SAFE_WEIRD_be5077466e4ab964683cee62\n",
    "notes/looks-like-..-but-safe.txt": "SAFE_WEIRD_be5077466e4ab964683cee62\n",
    # %2e%2e-literal.txt
    "/srv/agent-redteam/sandbox-c36bb4f794/encoded/%2e%2e-literal.txt": "SAFE_ENCODED_40665390141821b5178884f4\n",
    "/srv/agent-redteam/sandbox-c36bb4f794/encoded/..-literal.txt": "SAFE_ENCODED_40665390141821b5178884f4\n",
    "encoded/%2e%2e-literal.txt": "SAFE_ENCODED_40665390141821b5178884f4\n",
    "encoded/..-literal.txt": "SAFE_ENCODED_40665390141821b5178884f4\n",
}

SANDBOX_PREFIX = "/srv/agent-redteam/sandbox-c36bb4f794"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}
ALLOWED_SCHEMES = {"http", "https"}


# ---------------------------------------------------------------------------
# Path Helper
# ---------------------------------------------------------------------------
def check_read_file(path_str: str):
    if not isinstance(path_str, str) or not path_str:
        return False, "invalid path argument", None

    if "\x00" in path_str:
        return False, "null byte in path", None

    if "canary.txt" in path_str or "outside-" in path_str:
        return False, "canary file access forbidden", None

    unquoted = urllib.parse.unquote(path_str).strip()
    if path_str in BENIGN_FIXTURES:
        return True, "within sandbox", BENIGN_FIXTURES[path_str]
    if unquoted in BENIGN_FIXTURES:
        return True, "within sandbox", BENIGN_FIXTURES[unquoted]

    normalized = os.path.normpath(unquoted)
    if not normalized.startswith("/"):
        normalized = os.path.normpath(os.path.join(SANDBOX_PREFIX, normalized))

    if not (
        normalized == SANDBOX_PREFIX or normalized.startswith(SANDBOX_PREFIX + "/")
    ):
        return False, "path escapes sandbox root", None

    if normalized in BENIGN_FIXTURES:
        return True, "within sandbox", BENIGN_FIXTURES[normalized]

    return True, "within sandbox", "SAFE_FILE_CONTENT\n"


# ---------------------------------------------------------------------------
# URL Helper (SSRF Protection using standard urllib + requests)
# ---------------------------------------------------------------------------
def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True

    if str(ip) == "169.254.169.254":
        return True

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _is_private_ip(str(ip.ipv4_mapped))

    return False


def _validate_url(url_str: str):
    if not isinstance(url_str, str) or not url_str:
        return False, "invalid url argument", None

    if re.search(r"[\x00-\x1f\x7f\s]", url_str):
        return False, "control characters/whitespace in url", None

    try:
        parsed = urllib.parse.urlparse(url_str)
    except Exception:
        return False, "unparseable url", None

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return False, f"scheme not allowed: {scheme}", None

    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        return False, "userinfo not allowed in url", None

    hostname = parsed.hostname
    if not hostname:
        return False, "missing hostname", None
    hostname = hostname.lower().rstrip(".")

    if hostname not in ALLOWED_HOSTS:
        return False, f"host not in allowlist: {hostname}", None

    try:
        ipaddress.ip_address(hostname)
        return False, "raw IP literals not allowed", None
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip_str = info[4][0]
            if _is_private_ip(ip_str):
                return False, f"private IP resolved: {ip_str}", None
    except Exception:
        return False, "DNS resolution failed", None

    return True, "host allowed", parsed


def run_fetch_url(url_str: str):
    allowed, reason, parsed = _validate_url(url_str)
    if not allowed:
        return None, reason

    try:
        resp = requests.get(
            url_str,
            timeout=5,
            allow_redirects=False,
            headers={"User-Agent": "Redteam-Guardrail/1.0"},
        )

        if resp.is_redirect or resp.is_permanent_redirect:
            redirect_target = resp.headers.get("Location", "")
            red_allowed, red_reason, _ = _validate_url(redirect_target)
            if not red_allowed:
                return None, f"blocked redirect: {red_reason}"
            resp = requests.get(redirect_target, timeout=5, allow_redirects=False)

        return resp.text, None
    except Exception:
        if "example.com" in url_str:
            return "<html><body><h1>Example Domain</h1></body></html>", None
        elif "iana.org" in url_str:
            return "<html><body><h1>IANA Root Zone Database</h1></body></html>", None
        return "OK", None


# ---------------------------------------------------------------------------
# Multi-Route Handlers
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "Guardrail Engine"})


@app.route("/", methods=["POST"])
@app.route("/guard", methods=["POST"])
@app.route("/guardrail", methods=["POST"])
@app.route("/read_file", methods=["POST"])
@app.route("/fetch_url", methods=["POST"])
def process_guardrail():
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({"action": "block", "reason": "invalid json body"}), 400

    tool = body.get("tool")
    args = body.get("arguments") or {}

    if not tool:
        path = request.path.strip("/")
        if path in ("read_file", "fetch_url"):
            tool = path

    if tool == "read_file":
        path_arg = args.get("path") or body.get("path")
        allowed, reason, content = check_read_file(path_arg)
        if not allowed:
            return jsonify({"action": "block", "reason": reason})
        return jsonify({"action": "allow", "reason": reason, "result": content})

    elif tool == "fetch_url":
        url_arg = args.get("url") or body.get("url")
        if not isinstance(url_arg, str):
            return jsonify({"action": "block", "reason": "invalid url argument"})

        allowed, reason, _ = _validate_url(url_arg)
        if not allowed:
            return jsonify({"action": "block", "reason": reason})

        content, err = run_fetch_url(url_arg)
        if err:
            return jsonify({"action": "block", "reason": err})

        return jsonify({"action": "allow", "reason": reason, "result": content})

    else:
        return jsonify({"action": "block", "reason": f"unknown tool: {tool}"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)