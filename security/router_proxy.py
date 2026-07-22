import os
from urllib.parse import unquote

import requests
from dotenv import load_dotenv
from flask import Flask, Response, request

from detector import analyze

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
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

    print("--------------------------------")
    print(f"{request.method} {request.full_path}")
    print(f"Source IP: {source_ip}")

    if source_ip in diverted_ips:
        print("Already diverted -> Honeypot")
        print(
            f"[HONEYPOT-STICKY] "
            f"{request.method} {request.full_path} "
            f"from {source_ip}"
        )

        return HONEYPOT_URL

    if decision["action"] == "HONEYPOT":
        diverted_ips.add(source_ip)

        print(
            f'Attack detected: '
            f'{decision["attack_type"]}'
        )

        print(
            f'Reason: '
            f'{decision.get("reason", "No reason supplied")}'
        )

        print("Decision -> Honeypot")

        print(
            f"[HONEYPOT] "
            f"{request.method} {request.full_path} "
            f"from {source_ip}"
        )

        return HONEYPOT_URL

    print("Safe request -> Real Bank")

    print(
        f"[ALLOW] "
        f"{request.method} {request.full_path} "
        f"from {source_ip}"
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
        backend_response = requests.request(
            method=request.method,
            url=backend_url,

            params=request.args,

            data=request.get_data(cache=True),

            headers=create_backend_headers(),

            allow_redirects=False,

            timeout=30,
        )

        return create_client_response(backend_response)

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