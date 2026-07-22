import os
import time
from collections import defaultdict, deque
from threading import Lock


FLOOD_WINDOW_SECONDS = int(
    os.getenv("FLOOD_WINDOW_SECONDS", "10")
)

FLOOD_MAX_REQUESTS = int(
    os.getenv("FLOOD_MAX_REQUESTS", "30")
)


_request_history = defaultdict(deque)
_history_lock = Lock()


def detect_flood(source_ip):


    if not source_ip:
        return {
            "detected": False,
            "request_count": 0,
            "limit": FLOOD_MAX_REQUESTS,
            "window_seconds": FLOOD_WINDOW_SECONDS
        }

    current_time = time.monotonic()
    oldest_allowed_time = (
        current_time - FLOOD_WINDOW_SECONDS
    )

    with _history_lock:
        timestamps = _request_history[source_ip]


        while timestamps and timestamps[0] < oldest_allowed_time:
            timestamps.popleft()

        
        timestamps.append(current_time)

        request_count = len(timestamps)

    return {
        "detected": request_count > FLOOD_MAX_REQUESTS,
        "request_count": request_count,
        "limit": FLOOD_MAX_REQUESTS,
        "window_seconds": FLOOD_WINDOW_SECONDS
    }


def clear_flood_history(source_ip=None):


    with _history_lock:
        if source_ip:
            _request_history.pop(source_ip, None)
        else:
            _request_history.clear()


def get_request_count(source_ip):


    if not source_ip:
        return 0

    current_time = time.monotonic()
    oldest_allowed_time = (
        current_time - FLOOD_WINDOW_SECONDS
    )

    with _history_lock:
        timestamps = _request_history.get(source_ip)

        if not timestamps:
            return 0

        while timestamps and timestamps[0] < oldest_allowed_time:
            timestamps.popleft()

        return len(timestamps)