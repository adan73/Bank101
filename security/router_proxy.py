import os
from urllib.parse import unquote

import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    Response,
    jsonify,
    request,
    send_from_directory,
)

from detector import analyze
from blacklist import (
    add_to_blacklist,
    get_all_blacklisted,
    is_blacklisted,
    remove_from_blacklist,
)

from flood import clear_flood_history

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

ADMIN_FOLDER = os.path.join(
    os.path.dirname(__file__),
    "admin"
)

load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

app = Flask(__name__)

ROUTER_PORT = int(os.getenv("ROUTER_PORT", "8000"))

REAL_BANK_URL = "http://localhost:3000"
HONEYPOT_URL = "http://localhost:4000"

diverted_ips = set()


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def get_source_ip():


    forwarded_for = request.headers.get("X-Forwarded-For")

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.remote_addr or "unknown"




def build_detection_data():


    source_ip = get_source_ip()

    raw_url = request.full_path or request.path or ""

    try:
        decoded_url = unquote(unquote(raw_url))
    except (UnicodeDecodeError, ValueError):
        decoded_url = raw_url

    try:
        body_text = request.get_data(
            cache=True,
            as_text=True
        )
    except UnicodeDecodeError:
        body_text = ""

    headers_text = " ".join(
        f"{name}: {value}"
        for name, value in request.headers
    )

    raw_text = " ".join([
        raw_url,
        decoded_url,
        body_text,
        headers_text
    ])

    return {
        "raw_text": raw_text,
        "src_ip": source_ip,
        "method": request.method,
        "path": request.path
    }




def choose_target():
    detection_data = build_detection_data()
    decision = analyze(detection_data)

    source_ip = decision["source_ip"]

    print("\n" + "=" * 65)
    print(
        f"[ROUTER RECEIVED] "
        f"{request.method} {request.full_path} "
        f"from {source_ip}"
    )

    # This IP was already identified as an attacker earlier.
    if source_ip in diverted_ips:
        print("[ROUTER DECISION] IP was already diverted")
        print("[ROUTER DESTINATION] Honeypot")
        print(
            f"[ROUTER FORWARD] Will create a new request to "
            f"{HONEYPOT_URL}{request.path}"
        )

        return HONEYPOT_URL

    # A new attack was detected.
    if decision["action"] == "HONEYPOT":
        diverted_ips.add(source_ip)

        print(
            f"[ATTACK DETECTED] "
            f"{decision['attack_type']}"
        )
        print(
            f"[DETECTION REASON] "
            f"{decision.get('reason', 'No reason supplied')}"
        )
        print("[ROUTER DECISION] Redirect request to Honeypot")
        print("[ROUTER DESTINATION] Honeypot port 4000")
        print(
            f"[ROUTER FORWARD] Will create a new request to "
            f"{HONEYPOT_URL}{request.path}"
        )

        return HONEYPOT_URL

    # No attack was detected.
    print("[ROUTER DECISION] Request is safe")
    print("[ROUTER DESTINATION] Asset port 3000")
    print(
        f"[ROUTER FORWARD] Will create a new request to "
        f"{REAL_BANK_URL}{request.path}"
    )

    return REAL_BANK_URL


def create_backend_headers():


    headers = {}

    for name, value in request.headers:
        lower_name = name.lower()

        if lower_name == "host":
            continue

        if lower_name in HOP_BY_HOP_HEADERS:
            continue

        
        if lower_name == "content-length":
            continue

        headers[name] = value

    headers["X-Forwarded-For"] = get_source_ip()
    headers["X-Forwarded-Host"] = request.host
    headers["X-Forwarded-Proto"] = request.scheme

    return headers


def create_client_response(backend_response):


    excluded_response_headers = HOP_BY_HOP_HEADERS | {
        "content-length",
        "content-encoding",
    }

    response = Response(
        backend_response.content,
        status=backend_response.status_code,
    )

    for name in backend_response.raw.headers.keys():
        if name.lower() in excluded_response_headers:
            continue

        values = backend_response.raw.headers.getlist(name)

        for value in values:

            if name.lower() == "location":
                value = value.replace(
                    REAL_BANK_URL,
                    request.host_url.rstrip("/"),
                )
                value = value.replace(
                    HONEYPOT_URL,
                    request.host_url.rstrip("/"),
                )

            response.headers.add(name, value)

    return response


@app.get("/admin")
def admin_page():
    return send_from_directory(
        ADMIN_FOLDER,
        "admin.html"
    )


@app.get("/admin/admin.js")
def admin_javascript():
    return send_from_directory(
        ADMIN_FOLDER,
        "admin.js"
    )


@app.get("/admin/admin.css")
def admin_stylesheet():
    return send_from_directory(
        ADMIN_FOLDER,
        "admin.css"
    )


@app.get("/api/blacklist")
def api_get_blacklist():
    try:
        blacklisted_ips = get_all_blacklisted()

        return jsonify({
            "success": True,
            "blacklist": blacklisted_ips
        })

    except Exception as error:
        print(f"[ADMIN ERROR] Could not read blacklist: {error}")

        return jsonify({
            "success": False,
            "message": "Could not load blacklist"
        }), 500


@app.post("/api/blacklist/add")
def api_add_to_blacklist():
    data = request.get_json(silent=True) or {}

    ip = str(data.get("ip", "")).strip()
    reason = str(
        data.get("reason", "Added manually by administrator")
    ).strip()

    if not ip:
        return jsonify({
            "success": False,
            "message": "IP address is required"
        }), 400

    if is_blacklisted(ip):
        return jsonify({
            "success": False,
            "message": f"{ip} is already blacklisted"
        }), 409

    try:
        add_to_blacklist(ip, reason)

        # Keep the in memory Router state synchronized.
        diverted_ips.add(ip)

        print(f"[ADMIN] {ip} manually added to blacklist")
        print(f"[ADMIN] Reason: {reason}")

        return jsonify({
            "success": True,
            "message": f"{ip} was added to the blacklist"
        })

    except Exception as error:
        print(f"[ADMIN ERROR] Could not blacklist {ip}: {error}")

        return jsonify({
            "success": False,
            "message": "Could not add IP to blacklist"
        }), 500


@app.post("/api/blacklist/remove")
def api_remove_from_blacklist():
    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()

    if not ip:
        return jsonify({
            "success": False,
            "message": "IP address is required"
        }), 400

    if not is_blacklisted(ip):
        return jsonify({
            "success": False,
            "message": f"{ip} is not currently blacklisted"
        }), 404

    try:
        remove_from_blacklist(ip)

        # Remove the IP from the Router's sticky diversion state.
        diverted_ips.discard(ip)

        # clear the request counter so the IP does not immediately
        # trigger flooding detection again after being unblocked.
        clear_flood_history(ip)

        print(f"[ADMIN] {ip} removed from blacklist")
        print(f"[ADMIN] Sticky diversion cleared for {ip}")
        print(f"[ADMIN] Flood history cleared for {ip}")
        print(f"[ADMIN] {ip} may access the Asset again")

        return jsonify({
            "success": True,
            "message": (
                f"{ip} was removed from the blacklist "
                "and may access the Asset again"
            )
        })

    except Exception as error:
        print(f"[ADMIN ERROR] Could not unblock {ip}: {error}")

        return jsonify({
            "success": False,
            "message": "Could not remove IP from blacklist"
        }), 500




@app.route(
    "/",
    defaults={"path": ""},
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
    ],
)
@app.route(
    "/<path:path>",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
    ],
)
def proxy(path):
    target = choose_target()

    backend_url = f"{target}/{path}"

    try:
        backend_name = (
            "HONEYPOT"
            if target == HONEYPOT_URL
            else "ASSET"
        )

        print(
            f"[ROUTER SEND] Sending request to "
            f"{backend_name}: {backend_url}"
        )

        backend_response = requests.request(
            method=request.method,
            url=backend_url,
            params=request.args,
            data=request.get_data(cache=True),
            headers=create_backend_headers(),
            allow_redirects=False,
            timeout=30,
        )

        print(
            f"[ROUTER RESPONSE RECEIVED] "
            f"Status {backend_response.status_code} "
            f"received from {backend_name}"
        )

        client_response = create_client_response(backend_response)

        print(
            f"[ROUTER RETURN] Returning the "
            f"{backend_name} response to attacker "
            f"{get_source_ip()}"
        )

        return client_response

    except requests.exceptions.ConnectionError:
        print(f"Proxy error: backend unavailable at {target}")

        return Response(
            "Backend server is unavailable",
            status=502,
            content_type="text/plain",
        )

    except requests.exceptions.Timeout:
        print(f"Proxy error: backend timed out at {target}")

        return Response(
            "Backend server timed out",
            status=504,
            content_type="text/plain",
        )

    except requests.exceptions.RequestException as error:
        print(f"Proxy error: {error}")

        return Response(
            "Proxy request failed",
            status=502,
            content_type="text/plain",
        )


if __name__ == "__main__":
    print("Python router/proxy running")
    print(f"http://localhost:{ROUTER_PORT}")

    app.run(
        host="0.0.0.0",
        port=ROUTER_PORT,
        debug=False,
        threaded=True,
    )