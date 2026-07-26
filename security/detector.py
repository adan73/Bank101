from blacklist import (
    is_blacklisted,
    add_to_blacklist,
)

from flood import detect_flood
from sqli import detect_sqli
from attack_logger import log_attack


def analyze(request_data):
    """
    Expected request_data structure:
    {
        "raw_text": "...",
        "src_ip": "127.0.0.1",
        "method": "GET",
        "path": "/login"
    }
    """

    raw_text = str(request_data.get("raw_text", ""))

    source_ip = request_data.get("src_ip")
    method = request_data.get("method", "UNKNOWN")
    path = request_data.get("path", "")

    if is_blacklisted(source_ip):
        return {
            "action": "HONEYPOT",
            "attack_type": "BLACKLISTED_IP",
            "source_ip": source_ip,
            "reason": "Source IP is already blacklisted"
        }

    flood_result = detect_flood(source_ip)

    if flood_result["detected"]:

        reason = (
            f'{flood_result["request_count"]} requests received '
            f'in {flood_result["window_seconds"]} seconds; '
            f'limit is {flood_result["limit"]}'
        )

        add_to_blacklist(source_ip, reason)

        log_attack(
            ip=source_ip,
            attack_type="FLOODING",
            reason=reason,
            method=method,
            path=path
        )

        return {
            "action": "HONEYPOT",
            "attack_type": "FLOODING",
            "source_ip": source_ip,
            "reason": reason,
            "details": flood_result
        }

    print("RAW TEXT:")
    print(repr(raw_text))

    sqli_result = detect_sqli(raw_text)

    if sqli_result["detected"]:

        reason = f"SQL Injection detected ({sqli_result['pattern']})"

        add_to_blacklist(source_ip, reason)

        log_attack(
            ip=source_ip,
            attack_type="SQL_INJECTION",
            reason=reason,
            method=method,
            path=path
        )

        return {
            "action": "HONEYPOT",
            "attack_type": "SQL_INJECTION",
            "source_ip": source_ip,
            "reason": reason,
            "details": sqli_result
        }

    return {
        "action": "ALLOW",
        "attack_type": None,
        "source_ip": source_ip,
        "reason": None
    }