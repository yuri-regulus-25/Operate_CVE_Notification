import argparse
import json
import sqlite3
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path

import watch


DEFAULT_START = "2025-01-01T00:00:00Z"
MONTHLY_DIR = Path("docs") / "cve_monthly"

JVN_NAMESPACES = {
    "rss": "http://purl.org/rss/1.0/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "sec": "http://jvn.jp/rss/mod_sec/3.0/",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
}


def sanitize_text(value):
    if value is None:
        return ""

    text = str(value).replace("\x00", "")
    text = "".join(
        ch
        for ch in text
        if ch in ("\n", "\r", "\t") or ord(ch) >= 32
    )
    text = "".join(
        ch
        for ch in text
        if not (0xD800 <= ord(ch) <= 0xDFFF)
    )
    return text.encode("utf-8", errors="ignore").decode("utf-8", errors="ignore")


def sanitize_json(value):
    return sanitize_text(json.dumps(value, ensure_ascii=False))


def sanitize_alert(alert):
    return {
        key: sanitize_text(value) if isinstance(value, str) else value
        for key, value in alert.items()
    }


def parse_datetime(value, default=None):
    if not value:
        return default

    normalized = sanitize_text(value).strip()

    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    if "T" not in normalized:
        normalized = normalized + "T00:00:00+00:00"

    parsed = datetime.fromisoformat(normalized)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def require_month_start(start):
    if (
        start.day != 1
        or start.hour != 0
        or start.minute != 0
        or start.second != 0
        or start.microsecond != 0
    ):
        raise ValueError(
            "--start must be the first day of a UTC month at 00:00:00"
        )


def next_month_start(start):
    if start.month == 12:
        return start.replace(year=start.year + 1, month=1)

    return start.replace(month=start.month + 1)


def month_key(start):
    return f"{start.year:04d}_{start.month:02d}"


def monthly_paths(start):
    key = month_key(start)
    return (
        MONTHLY_DIR / f"cve_archive_{key}.sqlite",
        MONTHLY_DIR / f"cve_archive_{key}_summary.json",
    )


def format_sqlite_datetime(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()

    return sanitize_text(value)


def in_half_open_range(published, start, end):
    try:
        published_at = parse_datetime(published)
    except ValueError:
        return False

    return published_at is not None and start <= published_at < end


def date_windows(start, end, days):
    current = start

    while current <= end:
        window_end = min(current + timedelta(days=days - 1), end)
        yield current, window_end
        current = window_end + timedelta(days=1)


def ensure_schema(conn):
    conn.executescript(
        """
        PRAGMA journal_mode = DELETE;

        CREATE TABLE IF NOT EXISTS cve_records (
          source TEXT NOT NULL,
          source_id TEXT NOT NULL,
          cve_id TEXT NOT NULL,
          alert_id TEXT NOT NULL,
          category TEXT,
          product_key TEXT,
          matched TEXT,
          confidence TEXT,
          priority TEXT,
          severity TEXT,
          score REAL,
          published TEXT,
          last_modified TEXT,
          title TEXT,
          description TEXT,
          url TEXT,
          raw_json TEXT,
          first_seen_at TEXT NOT NULL,
          fetched_at TEXT NOT NULL,
          PRIMARY KEY (source, source_id)
        );

        CREATE INDEX IF NOT EXISTS idx_cve_records_cve_id
          ON cve_records (cve_id);

        CREATE INDEX IF NOT EXISTS idx_cve_records_published
          ON cve_records (published);

        CREATE INDEX IF NOT EXISTS idx_cve_records_last_modified
          ON cve_records (last_modified);

        CREATE INDEX IF NOT EXISTS idx_cve_records_product
          ON cve_records (product_key);

        CREATE TABLE IF NOT EXISTS cve_products (
          source TEXT NOT NULL,
          source_id TEXT NOT NULL,
          product_key TEXT NOT NULL,
          matched TEXT,
          category TEXT,
          confidence TEXT,
          updated_at TEXT NOT NULL,
          PRIMARY KEY (source, source_id, product_key)
        );

        CREATE TABLE IF NOT EXISTS cve_references (
          source TEXT NOT NULL,
          source_id TEXT NOT NULL,
          url TEXT NOT NULL,
          ref_source TEXT,
          tags_json TEXT,
          updated_at TEXT NOT NULL,
          PRIMARY KEY (source, source_id, url)
        );

        CREATE TABLE IF NOT EXISTS export_meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        """
    )


def set_meta(conn, values):
    for key, value in values.items():
        conn.execute(
            """
            INSERT INTO export_meta (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET
              value = excluded.value
            """,
            (sanitize_text(key), sanitize_text(value)),
        )


def get_existing_count(conn):
    return conn.execute("SELECT COUNT(*) FROM cve_records").fetchone()[0]


def upsert_alert(conn, alert, source_id, raw_json, references, fetched_at):
    alert = sanitize_alert(alert)
    source_id = sanitize_text(source_id)
    raw_json = sanitize_text(raw_json)
    fetched_at_text = format_sqlite_datetime(fetched_at)

    conn.execute(
        """
        INSERT INTO cve_records (
          source,
          source_id,
          cve_id,
          alert_id,
          category,
          product_key,
          matched,
          confidence,
          priority,
          severity,
          score,
          published,
          last_modified,
          title,
          description,
          url,
          raw_json,
          first_seen_at,
          fetched_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source, source_id) DO UPDATE SET
          cve_id = excluded.cve_id,
          alert_id = excluded.alert_id,
          category = excluded.category,
          product_key = excluded.product_key,
          matched = excluded.matched,
          confidence = excluded.confidence,
          priority = excluded.priority,
          severity = excluded.severity,
          score = excluded.score,
          published = excluded.published,
          last_modified = excluded.last_modified,
          title = excluded.title,
          description = excluded.description,
          url = excluded.url,
          raw_json = excluded.raw_json,
          fetched_at = excluded.fetched_at
        """,
        (
            alert.get("source", ""),
            source_id,
            alert.get("cve_id", ""),
            alert.get("alert_id", ""),
            alert.get("category", ""),
            alert.get("product_key", ""),
            alert.get("matched", ""),
            alert.get("confidence", ""),
            alert.get("priority", ""),
            alert.get("severity", ""),
            alert.get("score"),
            alert.get("published", ""),
            alert.get("last_modified", ""),
            alert.get("title", ""),
            alert.get("description", ""),
            alert.get("url", ""),
            raw_json,
            fetched_at_text,
            fetched_at_text,
        ),
    )

    if alert.get("product_key"):
        conn.execute(
            """
            INSERT INTO cve_products (
              source,
              source_id,
              product_key,
              matched,
              category,
              confidence,
              updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source, source_id, product_key) DO UPDATE SET
              matched = excluded.matched,
              category = excluded.category,
              confidence = excluded.confidence,
              updated_at = excluded.updated_at
            """,
            (
                alert.get("source", ""),
                source_id,
                alert.get("product_key", ""),
                alert.get("matched", ""),
                alert.get("category", ""),
                alert.get("confidence", ""),
                fetched_at_text,
            ),
        )

    for reference in references:
        url = sanitize_text(reference.get("url", ""))

        if not url:
            continue

        conn.execute(
            """
            INSERT INTO cve_references (
              source,
              source_id,
              url,
              ref_source,
              tags_json,
              updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(source, source_id, url) DO UPDATE SET
              ref_source = excluded.ref_source,
              tags_json = excluded.tags_json,
              updated_at = excluded.updated_at
            """,
            (
                alert.get("source", ""),
                source_id,
                url,
                sanitize_text(reference.get("source", "")),
                sanitize_json(reference.get("tags", [])),
                fetched_at_text,
            ),
        )


def nvd_references(cve):
    references = cve.get("references", [])

    if isinstance(references, dict):
        references = references.get("referenceData", [])

    return [
        {
            "url": reference.get("url", ""),
            "source": reference.get("source", ""),
            "tags": reference.get("tags", []),
        }
        for reference in references or []
    ]


def fetch_nvd_window(start, end):
    base_params = {
        "resultsPerPage": watch.NVD_RESULTS_PER_PAGE,
        "pubStartDate": watch.format_nvd_datetime(start),
        "pubEndDate": watch.format_nvd_datetime(end),
        "startIndex": 0,
    }

    vulnerabilities = []
    start_index = 0

    while True:
        params = dict(base_params)
        params["startIndex"] = start_index
        data = watch.fetch_nvd_page(params)

        page_items = data.get("vulnerabilities", [])
        results_per_page = data.get("resultsPerPage", len(page_items))
        total_results = data.get("totalResults", 0)

        print(
            "NVD monthly: "
            f"{start.isoformat()} <= published < {end.isoformat()}, "
            f"startIndex={start_index}, "
            f"pageItems={len(page_items)}, "
            f"totalResults={total_results}"
        )

        vulnerabilities.extend(page_items)

        if not page_items:
            break

        start_index += results_per_page

        if start_index >= total_results:
            break

        time.sleep(watch.NVD_REQUEST_DELAY)

    return vulnerabilities


def normalize_nvd_item(item):
    alerts = watch.normalize_nvd({"vulnerabilities": [item]})

    if not alerts:
        return None

    return alerts[0]


def export_nvd(conn, start, end, fetched_at):
    stats = {
        "windows": 1,
        "raw_items": 0,
        "accepted": 0,
        "out_of_range": 0,
    }

    vulnerabilities = fetch_nvd_window(start, end)
    stats["raw_items"] = len(vulnerabilities)

    for item in vulnerabilities:
        cve = item.get("cve", {})

        if not in_half_open_range(cve.get("published", ""), start, end):
            stats["out_of_range"] += 1
            continue

        alert = normalize_nvd_item(item)

        if not alert:
            continue

        source_id = cve.get("id") or alert.get("cve_id") or alert.get("alert_id")

        upsert_alert(
            conn=conn,
            alert=alert,
            source_id=source_id,
            raw_json=sanitize_json(item),
            references=nvd_references(cve),
            fetched_at=fetched_at,
        )
        stats["accepted"] += 1

    conn.commit()
    return stats


def fetch_jvn_window(keyword, start_date, end_date):
    base_params = {
        "method": "getVulnOverviewList",
        "feed": "hnd",
        "keyword": keyword,
        "useSynonym": "1",
        "rangeDatePublic": "n",
        "rangeDatePublished": "n",
        "rangeDateFirstPublished": "n",
        "startItem": 1,
        "maxCountItem": watch.JVN_RESULTS_PER_PAGE,
    }

    watch.update_jvn_date_params(
        base_params,
        "dateFirstPublished",
        start_date,
        end_date,
    )

    xml_pages = []
    start_item = 1

    while True:
        params = dict(base_params)
        params["startItem"] = start_item
        xml_text = watch.fetch_jvn_page(params)
        xml_pages.append(xml_text)

        status = watch.get_jvn_status(xml_text)
        total_results = watch.parse_int(status.get("totalRes"))
        page_items = watch.parse_int(status.get("totalResRet"))
        first_result = watch.parse_int(status.get("firstRes"), start_item)

        print(
            "JVN monthly: "
            f"keyword={keyword}, "
            f"{start_date} <= published <= {end_date}, "
            f"startItem={first_result}, "
            f"pageItems={page_items}, "
            f"totalResults={total_results}"
        )

        if page_items <= 0:
            break

        start_item = first_result + page_items

        if start_item > total_results:
            break

        time.sleep(0.6)

    return xml_pages


def xml_text(item, path):
    return item.findtext(path, default="", namespaces=JVN_NAMESPACES)


def normalize_jvn_item(item):
    title = xml_text(item, "rss:title")

    if "MyJVN　該当する脆弱性対策情報はありません。" in title:
        return None, "", []

    link = xml_text(item, "rss:link")
    identifier = xml_text(item, "sec:identifier")
    description = xml_text(item, "rss:description")
    cvss = item.find("sec:cvss", JVN_NAMESPACES)

    score = cvss.attrib.get("score", "") if cvss is not None else ""
    severity = (
        cvss.attrib.get("severity", "UNKNOWN").upper()
        if cvss is not None
        else "UNKNOWN"
    )

    cve_ids = [
        ref.attrib.get("id", "")
        for ref in item.findall("sec:references", JVN_NAMESPACES)
        if ref.attrib.get("source") == "CVE"
    ]

    product = watch.classify_product(
        title=title,
        description=description,
    )

    if not product:
        return None, "", []

    cve_id = cve_ids[0] if cve_ids else (identifier if identifier else title)
    source_id = identifier or cve_id or link or title
    matched = product["matched"]

    alert = {
        "alert_id": watch.make_alert_id("JVN", cve_id, matched),
        "source": "JVN",
        "category": product["category"],
        "product_key": product["product_key"],
        "confidence": product["confidence"],
        "priority": watch.decide_priority(severity),
        "cve_id": cve_id,
        "matched": matched,
        "severity": severity,
        "score": score,
        "published": xml_text(item, "dcterms:issued"),
        "last_modified": xml_text(item, "dcterms:modified"),
        "title": watch.truncate_text(title),
        "description": watch.truncate_text(description or title),
        "url": link,
    }

    references = [{"url": link, "source": "JVN", "tags": []}] if link else []

    return alert, source_id, references


def export_jvn(conn, start, end, fetched_at):
    stats = {
        "windows": 0,
        "raw_items": 0,
        "accepted": 0,
        "out_of_range": 0,
    }

    start_date = start.date()
    end_date = (end - timedelta(seconds=1)).date()

    for keyword in watch.JVN_KEYWORDS:
        for window_start, window_end in date_windows(start_date, end_date, 10):
            stats["windows"] += 1
            xml_pages = fetch_jvn_window(keyword, window_start, window_end)

            for xml_page in xml_pages:
                root = ET.fromstring(xml_page)
                items = root.findall(".//rss:item", JVN_NAMESPACES)
                stats["raw_items"] += len(items)

                for item in items:
                    alert, source_id, references = normalize_jvn_item(item)

                    if not alert:
                        continue

                    if not in_half_open_range(alert.get("published", ""), start, end):
                        stats["out_of_range"] += 1
                        continue

                    raw_payload = {
                        "item_xml": ET.tostring(item, encoding="unicode"),
                        "requested_keyword": keyword,
                    }

                    upsert_alert(
                        conn=conn,
                        alert=alert,
                        source_id=source_id,
                        raw_json=sanitize_json(raw_payload),
                        references=references,
                        fetched_at=fetched_at,
                    )
                    stats["accepted"] += 1

            conn.commit()
            time.sleep(0.6)

    return stats


def write_summary(conn, path, values):
    summary = dict(values)
    summary["database_counts"] = {
        "records": conn.execute("SELECT COUNT(*) FROM cve_records").fetchone()[0],
        "products": conn.execute("SELECT COUNT(*) FROM cve_products").fetchone()[0],
        "references": conn.execute("SELECT COUNT(*) FROM cve_references").fetchone()[0],
    }
    summary["sources"] = {
        row[0]: row[1]
        for row in conn.execute(
            "SELECT source, COUNT(*) FROM cve_records GROUP BY source"
        )
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Backfill one UTC month of CVE data into a SQLite archive."
    )
    parser.add_argument("--start", default=DEFAULT_START)
    parser.add_argument(
        "--source",
        choices=["all", "nvd", "jvn"],
        default="all",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    start = parse_datetime(args.start)
    require_month_start(start)
    end = next_month_start(start)
    db_path, summary_path = monthly_paths(start)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    fetched_at = datetime.now(timezone.utc)

    with sqlite3.connect(db_path) as conn:
        ensure_schema(conn)
        before_count = get_existing_count(conn)

        nvd_stats = None
        jvn_stats = None

        if args.source in ("all", "nvd"):
            nvd_stats = export_nvd(conn, start, end, fetched_at)

        if args.source in ("all", "jvn"):
            jvn_stats = export_jvn(conn, start, end, fetched_at)

        after_count = get_existing_count(conn)

        set_meta(
            conn,
            {
                "archive_type": "monthly",
                "month": month_key(start),
                "last_exported_at": fetched_at.isoformat(),
                "range_start": start.isoformat(),
                "range_end_exclusive": end.isoformat(),
                "source": args.source,
            },
        )
        conn.commit()

        summary = {
            "archive_type": "monthly",
            "generated_at": fetched_at.isoformat(),
            "month": month_key(start),
            "start": start.isoformat(),
            "end_exclusive": end.isoformat(),
            "source": args.source,
            "database": str(db_path),
            "records_before": before_count,
            "records_after": after_count,
            "nvd": nvd_stats,
            "jvn": jvn_stats,
        }
        write_summary(conn, summary_path, summary)

    print(
        f"Monthly SQLite export complete: {db_path} "
        f"({before_count} -> {after_count} records)"
    )
    print(f"Summary: {summary_path}")


if __name__ == "__main__":
    main()
