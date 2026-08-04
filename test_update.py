#!/usr/bin/env python3
"""
Standalone READ-ONLY verification script for the NVD incremental update process.

It calls the SAME NVD API endpoint that update.py uses and compares the CURRENT
state of the PostgreSQL database against the parsed API response.

- The endpoint URL is built with update.py's own builder (update.build_api_url).
- The HTTP fetch uses update.py's own retry/backoff logic
  (update.fetch_cve_page_with_retry).
- The response is parsed with update.py's own parser
  (update.parse_cve_entries).

So there is no copy of the endpoint/parsing logic — this test exercises the
exact code path the real update uses.

It performs NO writes to the database (no inserts, no updates, no DDL).
Run it before and/or after your manual update of update.py to confirm the DB
matches the endpoint response.

Usage:
    python3 test_update.py                                # last 24h window, up to 20 CVEs
    python3 test_update.py --window-hours 48              # last 48h window
    python3 test_update.py --limit 50                     # check up to 50 CVEs
    python3 test_update.py --results-per-page 5           # smaller API page (faster)
    python3 test_update.py --cve-id CVE-2021-4034         # check a single known CVE

Environment variables (same as update.py):
    DB_HOST, DB_NAME, DB_USER, DB_PASS, NVD_API_KEY

Exit code: 0 if all checks pass, 1 if any CVE does not match the DB.
"""

import sys
import time
import logging
import argparse
import urllib.request
import urllib.error
import json as _json
from datetime import datetime, timedelta, timezone

import psycopg2

# Reuse the REAL parsing / endpoint / fetch logic from update.py.
import update

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logger = logging.getLogger("nvd_update_test")


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    handler.setFormatter(formatter)

    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False


# ---------------------------------------------------------------------------
# Endpoint helpers (reuse update.py's own logic)
# ---------------------------------------------------------------------------

class _ResultsPerPageOverride:
    """Context manager that temporarily overrides update.py's RESULTS_PER_PAGE.

    update.build_api_url / fetch_cve_page_with_retry read the module-level
    RESULTS_PER_PAGE constant, so overriding it lets us keep exactly the same
    code path while controlling the page size.
    """

    def __init__(self, results_per_page: int):
        self.original = update.RESULTS_PER_PAGE
        self.results_per_page = results_per_page

    def __enter__(self):
        update.RESULTS_PER_PAGE = self.results_per_page
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        update.RESULTS_PER_PAGE = self.original


def build_api_url(start_index: int, last_mod_start: str, last_mod_end: str, results_per_page: int) -> str:
    """Build the time-window URL using update.py's own builder (same endpoint)."""
    with _ResultsPerPageOverride(results_per_page):
        return update.build_api_url(start_index, last_mod_start, last_mod_end)


def fetch_time_window_page(start_index: int, last_mod_start: str, last_mod_end: str, results_per_page: int) -> dict:
    """Fetch a time-window page using update.py's own retry/backoff logic."""
    with _ResultsPerPageOverride(results_per_page):
        return update.fetch_cve_page_with_retry(start_index, last_mod_start, last_mod_end)


def fetch_single_cve(cve_id: str, results_per_page: int) -> dict:
    """Fetch a single CVE from the SAME base endpoint, filtered by cveId.

    update.py itself uses the cveId filter nowhere, but the endpoint is the
    same (update.API_BASE) — this gives a deterministic target for verification.
    """
    url = (
        f"{update.API_BASE}?cveId={cve_id}"
        f"&resultsPerPage={results_per_page}"
        f"&startIndex=0"
    )
    headers = {"User-Agent": "nvd_scraper/1.0"}
    if update.NVD_API_KEY:
        headers["apiKey"] = update.NVD_API_KEY

    last_exc = None
    for attempt in range(1, 3):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req) as resp:
                return _json.loads(resp.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as exc:
            last_exc = exc
            time.sleep(1.0 * attempt)
    logger.error("Failed to fetch CVE %s: %s", cve_id, last_exc)
    return {}


# ---------------------------------------------------------------------------
# Read-only DB checks
# ---------------------------------------------------------------------------

REQUIRED_TABLES = (
    "cve_records",
    "cve_affected",
    "cve_versions",
    "cve_cpes",
    "cve_weaknesses",
)


def check_schema_exists(conn) -> tuple:
    """Verify (read-only) that all required tables exist.

    Returns (ok, missing_tables_list). Performs only SELECTs.
    """
    missing = []
    with conn.cursor() as cur:
        for table in REQUIRED_TABLES:
            cur.execute(
                "SELECT to_regclass(%s);",
                (table,),
            )
            if cur.fetchone()[0] is None:
                missing.append(table)
    return (len(missing) == 0, missing)


def db_counts(conn, cve_id: str) -> dict:
    """Return current DB row counts for a CVE (SELECTs only)."""
    with conn.cursor() as cur:
        cur.execute("SELECT raw_json IS NOT NULL FROM cve_records WHERE cve_id = %s;", (cve_id,))
        raw_row = cur.fetchone()

        cur.execute("SELECT COUNT(*) FROM cve_affected WHERE cve_id = %s;", (cve_id,))
        affected_count = cur.fetchone()[0]

        cur.execute(
            "SELECT COUNT(*) FROM cve_versions v "
            "JOIN cve_affected a ON a.id = v.affected_id WHERE a.cve_id = %s;",
            (cve_id,),
        )
        versions_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM cve_cpes WHERE cve_id = %s;", (cve_id,))
        cpes_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM cve_weaknesses WHERE cve_id = %s;", (cve_id,))
        weaknesses_count = cur.fetchone()[0]

    return {
        "raw_present": bool(raw_row and raw_row[0]),
        "affected": affected_count,
        "versions": versions_count,
        "cpes": cpes_count,
        "weaknesses": weaknesses_count,
    }


def db_sample_affected(conn, cve_id: str):
    """Return a sample (vendor, product) row for a CVE, if any (SELECT only)."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT vendor, product FROM cve_affected "
            "WHERE cve_id = %s AND vendor != '' AND product != '' LIMIT 1;",
            (cve_id,),
        )
        return cur.fetchone()


def db_sample_cpe(conn, cve_id: str):
    """Return a sample cpe for a CVE, if any (SELECT only)."""
    with conn.cursor() as cur:
        cur.execute("SELECT cpe FROM cve_cpes WHERE cve_id = %s LIMIT 1;", (cve_id,))
        row = cur.fetchone()
        return row[0] if row else None


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def compare_cve(conn, cve_id: str, affected_entries: list, cpe_entries: list, weakness_entries: list) -> list:
    """
    Compare the API-parsed data for one CVE against the CURRENT database.
    Returns a list of check results: (name, ok, detail).
    """
    checks = []

    # --- cve_records ---
    counts = db_counts(conn, cve_id)
    checks.append(
        ("cve_records.raw_json present", counts["raw_present"],
         "row exists with raw_json" if counts["raw_present"] else "row missing or raw_json NULL")
    )

    # --- cve_affected ---
    expected_affected = len(affected_entries)
    checks.append(
        ("cve_affected count", counts["affected"] == expected_affected,
         f"DB={counts['affected']} vs API={expected_affected}")
    )

    # --- cve_versions ---
    expected_versions = sum(len(a["versions"]) for a in affected_entries)
    checks.append(
        ("cve_versions count", counts["versions"] == expected_versions,
         f"DB={counts['versions']} vs API={expected_versions}")
    )

    # --- cve_cpes ---
    expected_cpes = len(cpe_entries)
    checks.append(
        ("cve_cpes count", counts["cpes"] == expected_cpes,
         f"DB={counts['cpes']} vs API={expected_cpes}")
    )

    # --- cve_weaknesses ---
    expected_weaknesses = len(weakness_entries)
    checks.append(
        ("cve_weaknesses count", counts["weaknesses"] == expected_weaknesses,
         f"DB={counts['weaknesses']} vs API={expected_weaknesses}")
    )

    # --- Sample field spot-checks (only if the API has that data) ---
    api_vendors = sorted({a["vendor"] for a in affected_entries if a["vendor"]})
    if api_vendors:
        sample = db_sample_affected(conn, cve_id)
        ok = bool(sample and sample[0] in api_vendors)
        detail = f"DB={sample[0] if sample else None} in API={api_vendors[:3]}{'...' if len(api_vendors) > 3 else ''}"
        checks.append(("cve_affected sample vendor", ok, detail))
    else:
        checks.append(("cve_affected sample vendor", True, "API has no vendor data (skipped)"))

    if cpe_entries:
        api_cpes = {c["cpe"] for c in cpe_entries}
        sample_cpe = db_sample_cpe(conn, cve_id)
        checks.append(
            ("cve_cpes sample cpe", sample_cpe in api_cpes,
             f"DB={sample_cpe} in API={len(cpe_entries)} cpes")
        )
    else:
        checks.append(("cve_cpes sample cpe", True, "API has no CPE data (skipped)"))

    return checks


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the current DB matches the NVD endpoint response (read-only, no writes)."
    )
    parser.add_argument("--window-hours", type=int, default=24,
                        help="Time window in hours to query (default: 24, same as update.py's first run).")
    parser.add_argument("--results-per-page", type=int, default=update.RESULTS_PER_PAGE,
                        help=f"Results per page (default: {update.RESULTS_PER_PAGE}, matches update.py).")
    parser.add_argument("--limit", type=int, default=20,
                        help="Maximum number of CVEs to verify (default: 20).")
    parser.add_argument("--cve-id",
                        help="Verify a single specific CVE instead of the time window.")
    args = parser.parse_args()

    setup_logging()

    logger.info("=" * 60)
    logger.info("NVD UPDATE VERIFICATION (read-only)")
    logger.info("=" * 60)
    logger.info("Endpoint base: %s", update.API_BASE)

    # ------------------------------------------------------------------
    # Connect to DB (SELECTs only)
    # ------------------------------------------------------------------
    try:
        conn = psycopg2.connect(
            host=update.DB_HOST, dbname=update.DB_NAME,
            user=update.DB_USER, password=update.DB_PASS,
        )
        logger.info("Connected to database %s on %s", update.DB_NAME, update.DB_HOST)
    except psycopg2.OperationalError as exc:
        logger.critical("Cannot connect to database: %s", exc)
        return 1

    # ------------------------------------------------------------------
    # Verify schema exists (read-only — no DDL)
    # ------------------------------------------------------------------
    schema_ok, missing = check_schema_exists(conn)
    if not schema_ok:
        logger.critical(
            "Database is missing required table(s): %s. "
            "Run ingest.py / update.py once to initialize the schema, then re-run this script.",
            ", ".join(missing),
        )
        conn.close()
        return 1
    logger.info("Database schema verified (%d tables present).", len(REQUIRED_TABLES))

    # ------------------------------------------------------------------
    # Call the same endpoint as update.py
    # ------------------------------------------------------------------
    now = datetime.now(timezone.utc)

    if args.cve_id:
        url = (
            f"{update.API_BASE}?cveId={args.cve_id}"
            f"&resultsPerPage={args.results_per_page}&startIndex=0"
        )
        logger.info("Fetching single CVE: %s", args.cve_id)
        logger.info("Endpoint URL: %s", url)

        fetch_start = time.time()
        data = fetch_single_cve(args.cve_id, args.results_per_page)
        fetch_seconds = time.time() - fetch_start
    else:
        start_date = now - timedelta(hours=args.window_hours)
        last_mod_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        last_mod_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
        logger.info("Time window: %s  →  %s", last_mod_start, last_mod_end)

        url = build_api_url(0, last_mod_start, last_mod_end, args.results_per_page)
        logger.info("Endpoint URL: %s", url)

        fetch_start = time.time()
        data = fetch_time_window_page(0, last_mod_start, last_mod_end, args.results_per_page)
        fetch_seconds = time.time() - fetch_start

    if not data:
        logger.critical("API returned no usable data. (Check NVD_API_KEY / network / URL above.)")
        conn.close()
        return 1

    total_results = data.get("totalResults", 0)
    vulnerabilities = data.get("vulnerabilities", [])
    logger.info("API totalResults=%d, vulnerabilities in page=%d (fetched in %.1fs)",
                total_results, len(vulnerabilities), fetch_seconds)

    # ------------------------------------------------------------------
    # Parse with update.py's own parser
    # ------------------------------------------------------------------
    entries = update.parse_cve_entries(vulnerabilities)
    parser_skipped = len(vulnerabilities) - len(entries)
    logger.info("Parsed %d CVEs (skipped %d entries without an ID).", len(entries), parser_skipped)

    if not entries:
        logger.warning("No CVEs to verify in the API response.")
        conn.close()
        return 0

    to_check = entries[: args.limit]
    if args.limit < len(entries):
        logger.info("Limiting verification to the first %d of %d CVEs.", args.limit, len(entries))

    # ------------------------------------------------------------------
    # Compare each CVE against the current DB
    # ------------------------------------------------------------------
    results = []  # (cve_id, passed_checks, total_checks, checks)

    for idx, (cve_id, _cve_data, affected_entries, cpe_entries, weakness_entries) in enumerate(to_check, 1):
        checks = compare_cve(conn, cve_id, affected_entries, cpe_entries, weakness_entries)
        passed = sum(1 for _, ok, _ in checks if ok)
        total = len(checks)
        results.append((cve_id, passed, total, checks))

        status = "PASS" if passed == total else "FAIL"
        logger.info("[%d/%d] %s: %s (%d/%d checks ok)", idx, len(to_check), cve_id, status, passed, total)
        for name, ok, detail in checks:
            mark = "  OK" if ok else "  XX"
            logger.info("%s %-32s %s", mark, name, detail)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    passed_cves = sum(1 for _, p, t, _ in results if p == t)
    failed_cves = len(results) - passed_cves

    logger.info("")
    logger.info("-" * 60)
    logger.info("VERIFICATION SUMMARY")
    logger.info("-" * 60)
    if args.cve_id:
        logger.info("  Target CVE:    %s", args.cve_id)
    else:
        logger.info("  Time window:   last %d hours", args.window_hours)
    logger.info("  Endpoint:      %s", url)
    logger.info("  API results:   %d (page returned %d)", total_results, len(vulnerabilities))
    logger.info("  CVEs checked:  %d", len(results))
    logger.info("  CVEs passed:   %d", passed_cves)
    logger.info("  CVEs failed:   %d", failed_cves)
    logger.info("  Duration:      %.1fs", time.time() - fetch_start)

    if failed_cves:
        logger.warning("The following CVEs do NOT match the endpoint response:")
        for cve_id, passed, total, checks in results:
            if passed != total:
                logger.warning("  - %s (%d/%d checks ok)", cve_id, passed, total)

    logger.info("-" * 60)
    logger.info("Verification %s", "PASSED" if failed_cves == 0 else "FAILED")
    logger.info("=" * 60)

    conn.close()
    return 0 if failed_cves == 0 else 1


if __name__ == "__main__":
    sys.exit(main())