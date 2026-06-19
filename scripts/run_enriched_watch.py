import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import enrich_alerts
import watch


watch.NVD_RESULTS_PER_PAGE = int(os.getenv("NVD_RESULTS_PER_PAGE", "500"))
watch.NVD_REQUEST_DELAY = float(os.getenv("NVD_REQUEST_DELAY", "1.5" if watch.NVD_API_KEY else "6.1"))
NVD_TIMEOUT = int(os.getenv("NVD_TIMEOUT", "60"))
NVD_RETRY_BASE_DELAY = float(os.getenv("NVD_RETRY_BASE_DELAY", "30.0"))
NVD_MAX_RETRIES = int(os.getenv("NVD_MAX_RETRIES", str(watch.NVD_MAX_RETRIES)))


def fetch_nvd_page_with_resilience(params):
    url = watch.NVD_API_URL + "?" + urllib.parse.urlencode(params)
    print(f"NVD URL: {url}")

    headers = {}
    if watch.NVD_API_KEY:
        headers["apiKey"] = watch.NVD_API_KEY

    request = urllib.request.Request(url, headers=headers)

    for attempt in range(1, NVD_MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(request, timeout=NVD_TIMEOUT) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            message = e.headers.get("message", "")
            print(
                "NVD request failed: "
                f"status={e.code}, "
                f"attempt={attempt}/{NVD_MAX_RETRIES}, "
                f"message={message or e.reason}"
            )

            if attempt >= NVD_MAX_RETRIES:
                raise

            time.sleep(NVD_RETRY_BASE_DELAY * attempt)
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as e:
            print(
                "NVD request failed: "
                f"attempt={attempt}/{NVD_MAX_RETRIES}, "
                f"reason={getattr(e, 'reason', e)}"
            )

            if attempt >= NVD_MAX_RETRIES:
                raise

            time.sleep(NVD_RETRY_BASE_DELAY * attempt)


watch.fetch_nvd_page = fetch_nvd_page_with_resilience


if __name__ == "__main__":
    enrich_alerts.main()
