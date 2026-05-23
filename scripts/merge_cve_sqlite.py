import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from export_cve_sqlite import sanitize_json, sanitize_text


MONTHLY_DIR = Path("docs") / "cve_monthly"
OUTPUT_DB_PATH = Path("docs") / "cve_archive.sqlite"
OUTPUT_SUMMARY_PATH = Path("docs") / "cve_archive_summary.json"


def parse_datetime_value(value):
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)

    text = sanitize_text(value).strip()

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    if "T" not in text:
        text = text + "T00:00:00+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


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
          PRIMARY KEY (source, cve_id)
        );

        CREATE INDEX IF NOT EXISTS idx_cve_records_source_id
          ON cve_records (source_id);

        CREATE INDEX IF NOT EXISTS idx_cve_records_published
          ON cve_records (published);

        CREATE INDEX IF NOT EXISTS idx_cve_records_last_modified
          ON cve_records (last_modified);

        CREATE INDEX IF NOT EXISTS idx_cve_records_product
          ON cve_records (product_key);

        CREATE TABLE IF NOT EXISTS cve_products (
          source TEXT NOT NULL,
          cve_id TEXT NOT NULL,
          product_key TEXT NOT NULL,
          matched TEXT,
          category TEXT,
          confidence TEXT,
          updated_at TEXT NOT NULL,
          PRIMARY KEY (source, cve_id, product_key)
        );

        CREATE TABLE IF NOT EXISTS cve_references (
          source TEXT NOT NULL,
          cve_id TEXT NOT NULL,
          url TEXT NOT NULL,
          ref_source TEXT,
          tags_json TEXT,
          updated_at TEXT NOT NULL,
          PRIMARY KEY (source, cve_id, url)
        );

        CREATE TABLE IF NOT EXISTS export_meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        """
    )


def row_dict(row):
    return {key: row[key] for key in row.keys()}


def sanitize_record(record):
    result = {}

    for key, value in record.items():
        if isinstance(value, str):
            result[key] = sanitize_text(value)
        else:
            result[key] = value

    if not result.get("cve_id"):
        result["cve_id"] = result.get("source_id", "")

    return result


def should_update(existing, incoming):
    if existing is None:
        return True

    return parse_datetime_value(incoming["last_modified"]) > parse_datetime_value(
        existing["last_modified"]
    )


def upsert_meta_if_changed(conn, key, value):
    key = sanitize_text(key)
    value = sanitize_text(value)
    current = conn.execute(
        "SELECT value FROM export_meta WHERE key = ?",
        (key,),
    ).fetchone()

    if current and current[0] == value:
        return False

    conn.execute(
        """
        INSERT INTO export_meta (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET
          value = excluded.value
        """,
        (key, value),
    )
    return True


def write_record(conn, record, first_seen_at):
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
        ON CONFLICT(source, cve_id) DO UPDATE SET
          source_id = excluded.source_id,
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
            record["source"],
            record["source_id"],
            record["cve_id"],
            record["alert_id"],
            record["category"],
            record["product_key"],
            record["matched"],
            record["confidence"],
            record["priority"],
            record["severity"],
            record["score"],
            record["published"],
            record["last_modified"],
            record["title"],
            record["description"],
            record["url"],
            record["raw_json"],
            first_seen_at,
            record["fetched_at"],
        ),
    )


def copy_products(target_conn, monthly_conn, record):
    target_conn.execute(
        "DELETE FROM cve_products WHERE source = ? AND cve_id = ?",
        (record["source"], record["cve_id"]),
    )

    rows = monthly_conn.execute(
        """
        SELECT *
        FROM cve_products
        WHERE source = ? AND source_id = ?
        """,
        (record["source"], record["source_id"]),
    ).fetchall()

    for row in rows:
        product = row_dict(row)
        target_conn.execute(
            """
            INSERT INTO cve_products (
              source,
              cve_id,
              product_key,
              matched,
              category,
              confidence,
              updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source, cve_id, product_key) DO UPDATE SET
              matched = excluded.matched,
              category = excluded.category,
              confidence = excluded.confidence,
              updated_at = excluded.updated_at
            """,
            (
                sanitize_text(product["source"]),
                record["cve_id"],
                sanitize_text(product["product_key"]),
                sanitize_text(product["matched"]),
                sanitize_text(product["category"]),
                sanitize_text(product["confidence"]),
                sanitize_text(product["updated_at"]),
            ),
        )


def copy_references(target_conn, monthly_conn, record):
    target_conn.execute(
        "DELETE FROM cve_references WHERE source = ? AND cve_id = ?",
        (record["source"], record["cve_id"]),
    )

    rows = monthly_conn.execute(
        """
        SELECT *
        FROM cve_references
        WHERE source = ? AND source_id = ?
        """,
        (record["source"], record["source_id"]),
    ).fetchall()

    for row in rows:
        reference = row_dict(row)
        target_conn.execute(
            """
            INSERT INTO cve_references (
              source,
              cve_id,
              url,
              ref_source,
              tags_json,
              updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(source, cve_id, url) DO UPDATE SET
              ref_source = excluded.ref_source,
              tags_json = excluded.tags_json,
              updated_at = excluded.updated_at
            """,
            (
                sanitize_text(reference["source"]),
                record["cve_id"],
                sanitize_text(reference["url"]),
                sanitize_text(reference["ref_source"]),
                sanitize_json(json.loads(reference["tags_json"] or "[]")),
                sanitize_text(reference["updated_at"]),
            ),
        )


def merge_monthly_file(target_conn, path):
    stats = {
        "file": str(path),
        "inserted": 0,
        "updated": 0,
        "skipped": 0,
    }

    with sqlite3.connect(path) as monthly_conn:
        monthly_conn.row_factory = sqlite3.Row
        rows = monthly_conn.execute(
            """
            SELECT *
            FROM cve_records
            ORDER BY source, cve_id, source_id
            """
        ).fetchall()

        for row in rows:
            incoming = sanitize_record(row_dict(row))
            existing = target_conn.execute(
                """
                SELECT *
                FROM cve_records
                WHERE source = ? AND cve_id = ?
                """,
                (incoming["source"], incoming["cve_id"]),
            ).fetchone()

            if not should_update(existing, incoming):
                stats["skipped"] += 1
                continue

            first_seen_at = (
                existing["first_seen_at"]
                if existing is not None
                else incoming["first_seen_at"]
            )

            write_record(target_conn, incoming, first_seen_at)
            copy_products(target_conn, monthly_conn, incoming)
            copy_references(target_conn, monthly_conn, incoming)

            if existing is None:
                stats["inserted"] += 1
            else:
                stats["updated"] += 1

    return stats


def monthly_sqlite_files():
    return sorted(MONTHLY_DIR.glob("cve_archive_????_??.sqlite"))


def database_counts(conn):
    return {
        "records": conn.execute("SELECT COUNT(*) FROM cve_records").fetchone()[0],
        "products": conn.execute("SELECT COUNT(*) FROM cve_products").fetchone()[0],
        "references": conn.execute("SELECT COUNT(*) FROM cve_references").fetchone()[0],
    }


def source_counts(conn):
    return {
        row[0]: row[1]
        for row in conn.execute(
            "SELECT source, COUNT(*) FROM cve_records GROUP BY source"
        )
    }


def max_last_modified(conn):
    row = conn.execute("SELECT MAX(last_modified) FROM cve_records").fetchone()
    return row[0] or ""


def write_summary(conn, path, files):
    summary = {
        "archive_type": "merged",
        "monthly_files": [str(file).replace("\\", "/") for file in files],
        "database": str(OUTPUT_DB_PATH).replace("\\", "/"),
        "database_counts": database_counts(conn),
        "sources": source_counts(conn),
        "max_last_modified": max_last_modified(conn),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def main():
    files = monthly_sqlite_files()

    if not files:
        raise FileNotFoundError(f"No monthly SQLite files found in {MONTHLY_DIR}")

    OUTPUT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(OUTPUT_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        ensure_schema(conn)

        all_stats = []

        for file in files:
            stats = merge_monthly_file(conn, file)
            all_stats.append(stats)
            print(
                f"Merged {file}: "
                f"inserted={stats['inserted']}, "
                f"updated={stats['updated']}, "
                f"skipped={stats['skipped']}"
            )

        counts = database_counts(conn)
        upsert_meta_if_changed(conn, "archive_type", "merged")
        upsert_meta_if_changed(conn, "monthly_file_count", str(len(files)))
        upsert_meta_if_changed(conn, "record_count", str(counts["records"]))
        upsert_meta_if_changed(conn, "max_last_modified", max_last_modified(conn))
        conn.commit()

        write_summary(conn, OUTPUT_SUMMARY_PATH, files)

    inserted = sum(item["inserted"] for item in all_stats)
    updated = sum(item["updated"] for item in all_stats)
    skipped = sum(item["skipped"] for item in all_stats)

    print(
        "SQLite merge complete: "
        f"inserted={inserted}, updated={updated}, skipped={skipped}"
    )
    print(f"Database: {OUTPUT_DB_PATH}")
    print(f"Summary: {OUTPUT_SUMMARY_PATH}")


if __name__ == "__main__":
    main()
