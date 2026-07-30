#!/usr/bin/env python3
"""
Daily incremental update script for NVD CVE data.
Fetches CVEs modified in the last 24 hours from the NIST NVD API 2.0
and upserts them into the PostgreSQL database.
"""

import os
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
import psycopg2
import psycopg2.extras

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "nvd_db")
DB_USER = os.getenv("DB_USER", "nvd_user")
DB_PASS = os.getenv("DB_PASS", "nvd_password")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
REQUEST_DELAY = 0.6  # seconds between requests (with API key: 50 req/30s = 0.6s)


def init_db(conn):
    """Ensure all tables and the update_tracker exist."""
    with conn.cursor() as cur:
        # Main CVE table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cve_records (
                cve_id VARCHAR(50) PRIMARY KEY,
                raw_json JSONB
            );
        """)
        # Affected products table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cve_affected (
                id SERIAL PRIMARY KEY,
                cve_id VARCHAR(50) REFERENCES cve_records(cve_id) ON DELETE CASCADE,
                source VARCHAR,
                vendor TEXT,
                product TEXT,
                default_status VARCHAR,
                repo TEXT,
                program_files TEXT[]
            );
        """)
        # Version details table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cve_versions (
                id SERIAL PRIMARY KEY,
                affected_id INTEGER REFERENCES cve_affected(id) ON DELETE CASCADE,
                version VARCHAR,
                status VARCHAR,
                less_than VARCHAR,
                less_than_or_equal VARCHAR,
                version_type VARCHAR
            );
        """)
        # Indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor ON cve_affected (vendor);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_affected_product ON cve_affected (product);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_versions_version ON cve_versions (version);")
        # Update tracker
        cur.execute("""
            CREATE TABLE IF NOT EXISTS update_tracker (
                id INT PRIMARY KEY DEFAULT 1,
                last_run TIMESTAMP
            );
        """)
    conn.commit()


def get_last_run(conn):
    """Get the timestamp of the last successful update."""
    with conn.cursor() as cur:
        cur.execute("SELECT last_run FROM update_tracker WHERE id = 1;")
        row = cur.fetchone()
        if row:
            return row[0]
    return None


def set_last_run(conn, timestamp):
    """Store the timestamp of the last successful update."""
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO update_tracker (id, last_run)
            VALUES (1, %s)
            ON CONFLICT (id) DO UPDATE SET last_run = EXCLUDED.last_run;
        """, (timestamp,))
    conn.commit()


def fetch_cve_page(start_index, last_mod_start, last_mod_end):
    """Fetch a single page of CVEs from the NVD API."""
    url = (
        f"{API_BASE}?lastModStartDate={last_mod_start}"
        f"&lastModEndDate={last_mod_end}"
        f"&resultsPerPage={RESULTS_PER_PAGE}"
        f"&startIndex={start_index}"
    )

    headers = {"User-Agent": "nvd_scraper/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data
    except urllib.error.HTTPError as e:
        print(f"[ERROR] HTTP {e.code} for startIndex={start_index}: {e.reason}")
        if e.code == 403:
            print("[ERROR] API key may be invalid or rate limited.")
        return None
    except Exception as e:
        print(f"[ERROR] Request failed for startIndex={start_index}: {e}")
        return None


def parse_cve_entries(vulnerabilities):
    """Parse the vulnerabilities array from the API response into structured records."""
    results = []

    for vuln in vulnerabilities:
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id")
        if not cve_id:
            continue

        # Extract affected structure (NVD API 2.0 format)
        affected_list = cve_data.get("affected", [])
        structured_affected = []

        for affected_entry in affected_list:
            source = affected_entry.get("source", "")
            affected_data_list = affected_entry.get("affectedData", [])

            for ad in affected_data_list:
                vendor = ad.get("vendor", "")
                product = ad.get("product", "")
                default_status = ad.get("defaultStatus", "")
                repo = ad.get("repo", "")
                program_files = ad.get("programFiles", [])

                versions = []
                for v in ad.get("versions", []):
                    versions.append({
                        "version": v.get("version", ""),
                        "status": v.get("status", ""),
                        "less_than": v.get("lessThan", ""),
                        "less_than_or_equal": v.get("lessThanOrEqual", ""),
                        "version_type": v.get("versionType", "")
                    })

                structured_affected.append({
                    "source": source,
                    "vendor": vendor,
                    "product": product,
                    "default_status": default_status,
                    "repo": repo,
                    "program_files": program_files,
                    "versions": versions
                })

        results.append((cve_id, cve_data, structured_affected))

    return results


def upsert_cve(conn, cve_id, cve_data, affected_entries):
    """Insert or update a single CVE and its related data."""
    with conn.cursor() as cur:
        # 1. Insert/update main CVE record
        cur.execute("""
            INSERT INTO cve_records (cve_id, raw_json)
            VALUES (%s, %s)
            ON CONFLICT (cve_id) DO UPDATE SET
                raw_json = EXCLUDED.raw_json;
        """, (cve_id, psycopg2.extras.Json(cve_data)))

        # 2. Delete old affected data for this CVE
        cur.execute("DELETE FROM cve_affected WHERE cve_id = %s;", (cve_id,))

        # 3. Insert new affected data and versions
        for aff in affected_entries:
            cur.execute("""
                INSERT INTO cve_affected
                    (cve_id, source, vendor, product, default_status, repo, program_files)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id;
            """, (
                cve_id,
                aff["source"],
                aff["vendor"],
                aff["product"],
                aff["default_status"],
                aff["repo"],
                aff["program_files"]
            ))
            affected_id = cur.fetchone()[0]

            for v in aff["versions"]:
                cur.execute("""
                    INSERT INTO cve_versions
                        (affected_id, version, status, less_than, less_than_or_equal, version_type)
                    VALUES (%s, %s, %s, %s, %s, %s);
                """, (
                    affected_id,
                    v["version"],
                    v["status"],
                    v["less_than"],
                    v["less_than_or_equal"],
                    v["version_type"]
                ))


def main():
    print(f"[{datetime.now(timezone.utc).isoformat()}] NVD update started.")

    conn = psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS)
    init_db(conn)
    conn.autocommit = False

    # Determine the time window
    last_run = get_last_run(conn)
    now = datetime.now(timezone.utc)

    if last_run:
        # Use the last successful run as the start (avoid gaps)
        start_date = last_run
    else:
        # First run: fetch last 24 hours
        start_date = now - timedelta(hours=24)

    # NVD API requires ISO 8601 format with milliseconds
    last_mod_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    last_mod_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    print(f"  Fetching CVEs modified from {last_mod_start} to {last_mod_end}")

    total_processed = 0
    start_index = 0
    total_results = None

    while True:
        print(f"  Fetching page (startIndex={start_index})...")
        data = fetch_cve_page(start_index, last_mod_start, last_mod_end)

        if data is None:
            print("[ERROR] Failed to fetch data. Will retry on next run.")
            conn.close()
            return

        if total_results is None:
            total_results = data.get("totalResults", 0)
            print(f"  Total results available: {total_results}")

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            print("  No more results.")
            break

        # Parse and insert
        entries = parse_cve_entries(vulnerabilities)
        for cve_id, cve_data, affected_entries in entries:
            try:
                upsert_cve(conn, cve_id, cve_data, affected_entries)
                total_processed += 1
            except Exception as e:
                print(f"  [ERROR] Failed to upsert {cve_id}: {e}")
                conn.rollback()
                continue

        conn.commit()
        print(f"  Processed {total_processed} / {total_results} CVEs...")

        # Check if there are more pages
        start_index += RESULTS_PER_PAGE
        if start_index >= total_results:
            break

        # Rate limiting delay
        time.sleep(REQUEST_DELAY)

    # Record the successful run timestamp
    set_last_run(conn, now)
    conn.close()

    print(f"[{datetime.now(timezone.utc).isoformat()}] NVD update completed.")
    print(f"  Processed {total_processed} CVEs.")


if __name__ == "__main__":
    main()