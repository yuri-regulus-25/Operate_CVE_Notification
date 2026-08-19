import json
import time
import urllib.error
import urllib.request


DEFAULT_TIMEOUT = 60


def fetch_text(url, headers=None, timeout=DEFAULT_TIMEOUT, retries=3, retry_base_delay=10):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "external-service-risk-watch/1.0",
            **(headers or {}),
        },
    )

    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as error:
            if error.code not in (429, 500, 502, 503, 504) or attempt >= retries:
                raise
            time.sleep(retry_base_delay * attempt)
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt >= retries:
                raise
            time.sleep(retry_base_delay * attempt)


def fetch_json(url, headers=None, timeout=DEFAULT_TIMEOUT, retries=3, retry_base_delay=10):
    return json.loads(
        fetch_text(
            url,
            headers=headers,
            timeout=timeout,
            retries=retries,
            retry_base_delay=retry_base_delay,
        )
    )
