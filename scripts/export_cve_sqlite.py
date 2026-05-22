import argparse
import calendar
import json
import sqlite3
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path

import watch


DEFAULT_START = "2025-01-01T00:00:00Z"
DEFAULT_DB_PATH = Path("docs") / "cve_archive.sqlite"
DEFAULT_SUMMARY_PATH = Path("docs") / "cve_archive_summary.json"

JVN_NAMESPACES = {
    "rss": "http://purl.org/rss/1.0/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "sec": "http://jvn.jp/rss/mod_sec/3.0/",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
}


def parse_datetime(value, default=None):
    if not value:
        return default

    normalized = value.strip()

    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    if "T" not in normalized:
        normalized = normalized + "T00:00:00+00:00"

    parsed = datetime.fromisoformat(normalized)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def format_sqlite_datetime(value):
    if not value:
        return ""

    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()

    return str(value)


def month_windows(start, end):
    current = start.replace(microsecond=0)
    end = end.replace(microsecond=0)

    while current <= end:
        last_day = calendar.monthrange(current.year, current.month)[1]
        month_end = current.replace(
            day=last_day,
            hour=23,
            minute=59,
            second=59,
        )
        window_end = min(month_end, end)
        yield current, window_end

        if window_end >= end:
            break

        current = (window_end + timedelta(seconds=1)).replace(
            hour=0,
            minute=0,
            second=0,
        )


def day_windows(start, end, days):
    current = start.replace(microsecond=0)
    end = end.replace(microsecond=0)

    while current <= end:
        window_end = min(
            current + timedelta(days=days) - timedelta(seconds=1),
            end,
        )
        yield current, window_end

        if window_end >= end:
            break

        current = window_end + timedelta(seconds=1)


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


def upsert_alert(conn, alert, source_id, raw_json, references, fetched_at):
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
        url = reference.get("url", "")

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
                reference.get("source", ""),
                json.dumps(reference.get("tags", []), ensure_ascii=False),
                fetched_at_text,
            ),
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
            (key, str(value)),
        )


def get_existing_count(conn):
    return conn.execute("SELECT COUNT(*) FROM cve_records").fetchone()[0]


def nvd_references(cve):
    references = cve.get("references", [])

    if isinstance(references, dict):
        references = references.get("referenceData", [])

    result = []

    for reference in references or []:
        result.append({
            "url": reference.get("url", ""),
            "source": reference.get("source", ""),
            "tags": reference.get("tags", []),
        })

    return result


def fetch_nvd_window(start, end):
    base_params = {
        "resultsPerPage": watch.NVD_RESULTS_PER_PAGE,
        "pubStartDate": watch.format_nvd_datetime(start),
        "pubEndDate": watch.format_nvd_datetime(end),
        "startIndex": 0,
    }

    vulnerabilities = []
    start_index = 0
    total_results = 0

    while True:
        params = dict(base_params)
        params["startIndex"] = start_index
        data = watch.fetch_nvd_page(params)

        page_items = data.get("vulnerabilities", [])
        results_per_page = data.get("resultsPerPage", len(page_items))
        total_results = data.get("totalResults", 0)

        print(
            "NVD backfill: "
            f"{start.isoformat()} - {end.isoformat()}, "
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
        "windows": 0,
        "raw_items": 0,
        "accepted": 0,
    }

    for window_start, window_end in month_windows(start, end):
        stats["windows"] += 1
        vulnerabilities = fetch_nvd_window(window_start, window_end)
        stats["raw_items"] += len(vulnerabilities)

        for item in vulnerabilities:
            alert = normalize_nvd_item(item)

            if not alert:
                continue

            cve = item.get("cve", {})
            source_id = cve.get("id") or alert.get("cve_id") or alert.get("alert_id")

            upsert_alert(
                conn=conn,
                alert=alert,
                source_id=source_id,
                raw_json=json.dumps(item, ensure_ascii=False),
                references=nvd_references(cve),
                fetched_at=fetched_at,
            )
            stats["accepted"] += 1

        conn.commit()
        time.sleep(watch.NVD_REQUEST_DELAY)

    return stats


def fetch_jvn_window(keyword, start, end):
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
        start,
        end,
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
            "JVN backfill: "
            f"keyword={keyword}, "
            f"{start} - {end}, "
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


def text(item, path):
    return item.findtext(path, default="", namespaces=JVN_NAMESPACES)


def normalize_jvn_item(item):
    title = text(item, "rss:title")

    if "MyJVN　該当する脆弱性対策情報はありません。" in title:
        return None, "", []

    link = text(item, "rss:link")
    identifier = text(item, "sec:identifier")
    description = text(item, "rss:description")
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
        "published": text(item, "dcterms:issued"),
        "last_modified": text(item, "dcterms:modified"),
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
    }

    start_date = start.astimezone(watch.JVN_TIMEZONE).date()
    end_date = end.astimezone(watch.JVN_TIMEZONE).date()

    for keyword in watch.JVN_KEYWORDS:
        for window_start, window_end in date_windows(start_date, end_date, 10):
            stats["windows"] += 1
            xml_pages = fetch_jvn_window(keyword, window_start, window_end)

            for xml_text in xml_pages:
                root = ET.fromstring(xml_text)
                items = root.findall(".//rss:item", JVN_NAMESPACES)
                stats["raw_items"] += len(items)

                for item in items:
                    alert, source_id, references = normalize_jvn_item(item)

                    if not alert:
                        continue

                    raw_payload = {
                        "requested_keyword": keyword,
                        "item_xml": ET.tostring(item, encoding="unicode"),
                    }

                    upsert_alert(
                        conn=conn,
                        alert=alert,
                        source_id=source_id,
                        raw_json=json.dumps(raw_payload, ensure_ascii=False),
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
        description="Backfill CVE data into a SQLite archive."
    )
    parser.add_argument("--start", default=DEFAULT_START)
    parser.add_argument("--end", default="")
    parser.add_argument("--db-path", default=str(DEFAULT_DB_PATH))
    parser.add_argument("--summary-path", default=str(DEFAULT_SUMMARY_PATH))
    parser.add_argument(
        "--source",
        choices=["all", "nvd", "jvn"],
        default="all",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    start = parse_datetime(args.start)
    end = parse_datetime(args.end, datetime.now(timezone.utc))

    if start > end:
        raise ValueError("--start must be earlier than --end")

    db_path = Path(args.db_path)
    summary_path = Path(args.summary_path)
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

        meta = {
            "last_exported_at": fetched_at.isoformat(),
            "last_export_start": start.isoformat(),
            "last_export_end": end.isoformat(),
            "last_export_source": args.source,
        }
        set_meta(conn, meta)
        conn.commit()

        summary = {
            "generated_at": fetched_at.isoformat(),
            "start": start.isoformat(),
            "end": end.isoformat(),
            "source": args.source,
            "records_before": before_count,
            "records_after": after_count,
            "nvd": nvd_stats,
            "jvn": jvn_stats,
        }
        write_summary(conn, summary_path, summary)

    print(
        f"SQLite export complete: {db_path} "
        f"({before_count} -> {after_count} records)"
    )
    print(f"Summary: {summary_path}")


if __name__ == "__main__":
    main()
