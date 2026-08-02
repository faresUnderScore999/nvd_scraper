#!/usr/bin/env python3
"""
Daily incremental update script for NVD CVE data.
Fetches CVEs modified in the last 24 hours from the NIST NVD API 2.0
and upserts them into the PostgreSQL database.

Improvements over v1:
  - Structured logging with timestamps and log levels
  - Retry with exponential backoff on API failures
  - Per-page and per-CVE success/failure tracking
  - Persistent update_run_log table for audit history
  - Pagination resilience (skip bad pages, continue)
  - DB connection health checks with auto-reconnect
  - Graceful shutdown on SIGINT/SIGTERM
  - Detailed summary report at end of run
"""

import os
import sys
import json
import time
import signal
import logging
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "nvd_db")
DB_USER = os.getenv("DB_USER", "nvd_user")
DB_PASS = os.getenv("DB_PASS", "nvd_password")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
REQUEST_DELAY = 0.6  # seconds between normal requests (with API key: 50 req/30s = 0.6s)

MAX_RETRIES = 5
BACKOFF_BASE_DELAY = 1.0  # seconds for first retry
BACKOFF_MAX_DELAY = 60.0  # cap for exponential backoff

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logger = logging.getLogger("nvd_update")


def setup_logging() -> None:
    """Configure structured logging with timestamps and level prefixes."""
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False


# ---------------------------------------------------------------------------
# Graceful shutdown support
# ---------------------------------------------------------------------------

shutdown_requested = False


def _signal_handler(signum: int, frame) -> None:
    """Handle SIGINT/SIGTERM by setting a global flag checked in the main loop."""
    global shutdown_requested
    if shutdown_requested:
        logger.warning("Second signal received, forcing immediate exit.")
        sys.exit(1)
    shutdown_requested = True
    logger.warning(
        "Shutdown requested (signal %d). Finishing current page, then exiting...",
        signum,
    )


def register_signal_handlers() -> None:
    """Register signal handlers for graceful shutdown."""
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def init_db(conn) -> None:
    """Ensure all tables (including update_run_log) exist."""
    with conn.cursor() as cur:
        # Enable pg_trgm extension for fuzzy text matching
        cur.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")

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
        # CPE match table (from configurations[].nodes[].cpeMatch[])
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cve_cpes (
                id SERIAL PRIMARY KEY,
                cve_id VARCHAR(50) REFERENCES cve_records(cve_id) ON DELETE CASCADE,
                cpe TEXT NOT NULL,
                vulnerable BOOLEAN,
                match_criteria_id VARCHAR(100)
            );
        """)
        # Indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor ON cve_affected (vendor);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_affected_product ON cve_affected (product);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_versions_version ON cve_versions (version);")

        # Trigram indexes for fuzzy/partial matching on vendor and product
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor_trgm ON cve_affected USING gin (vendor gin_trgm_ops);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_affected_product_trgm ON cve_affected USING gin (product gin_trgm_ops);")

        # Indexes for CPE lookups (trigram index supports LIKE '%...%' queries)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_cpes_cve_id ON cve_cpes (cve_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_cpes_cpe_trgm ON cve_cpes USING gin (cpe gin_trgm_ops);")

        # Update tracker (last successful run timestamp)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS update_tracker (
                id INT PRIMARY KEY DEFAULT 1,
                last_run TIMESTAMP
            );
        """)

        # Persistent run history log
        cur.execute("""
            CREATE TABLE IF NOT EXISTS update_run_log (
                id SERIAL PRIMARY KEY,
                started_at TIMESTAMP NOT NULL DEFAULT NOW(),
                finished_at TIMESTAMP,
                status VARCHAR(20) NOT NULL DEFAULT 'running',
                total_results INTEGER DEFAULT 0,
                pages_total INTEGER DEFAULT 0,
                pages_succeeded INTEGER DEFAULT 0,
                pages_failed INTEGER DEFAULT 0,
                cves_total INTEGER DEFAULT 0,
                cves_succeeded INTEGER DEFAULT 0,
                cves_failed INTEGER DEFAULT 0,
                cves_skipped INTEGER DEFAULT 0,
                errors TEXT[] DEFAULT '{}'
            );
        """)
    conn.commit()


def ensure_db_connection(conn, max_retries: int = 3) -> psycopg2.extensions.connection:
    """Check the DB connection is alive; reconnect if necessary."""
    for attempt in range(1, max_retries + 1):
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
            return conn
        except psycopg2.OperationalError as exc:
            logger.warning(
                "DB connection lost (attempt %d/%d): %s. Reconnecting...",
                attempt, max_retries, exc,
            )
            try:
                conn.close()
            except Exception:
                pass
            try:
                conn = psycopg2.connect(
                    host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS
                )
                # Reinitialize the schema on the new connection
                init_db(conn)
                logger.info("DB reconnection successful.")
            except psycopg2.OperationalError as reconnect_err:
                logger.error("Reconnection failed: %s", reconnect_err)
                if attempt < max_retries:
                    time.sleep(2 ** attempt)
                else:
                    raise
    return conn


def get_last_run(conn):
    """Get the timestamp of the last successful update."""
    with conn.cursor() as cur:
        cur.execute("SELECT last_run FROM update_tracker WHERE id = 1;")
        row = cur.fetchone()
        if row:
            return row[0]
    return None


def set_last_run(conn, timestamp) -> None:
    """Store the timestamp of the last successful update."""
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO update_tracker (id, last_run)
            VALUES (1, %s)
            ON CONFLICT (id) DO UPDATE SET last_run = EXCLUDED.last_run;
        """, (timestamp,))
    conn.commit()


def create_run_log(conn) -> int:
    """Insert a new update_run_log entry and return its ID."""
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO update_run_log (started_at, status)
            VALUES (NOW(), 'running')
            RETURNING id;
        """)
        run_id = cur.fetchone()[0]
    conn.commit()
    return run_id


def finalize_run_log(conn, run_id: int, status: str, **counts) -> None:
    """Update the run log with final status, duration, and counters."""
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE update_run_log
            SET finished_at = NOW(),
                status = %s,
                total_results = %s,
                pages_total = %s,
                pages_succeeded = %s,
                pages_failed = %s,
                cves_total = %s,
                cves_succeeded = %s,
                cves_failed = %s,
                cves_skipped = %s
            WHERE id = %s;
        """, (
            status,
            counts.get("total_results", 0),
            counts.get("pages_total", 0),
            counts.get("pages_succeeded", 0),
            counts.get("pages_failed", 0),
            counts.get("cves_total", 0),
            counts.get("cves_succeeded", 0),
            counts.get("cves_failed", 0),
            counts.get("cves_skipped", 0),
            run_id,
        ))
    conn.commit()


def append_run_error(conn, run_id: int, error_msg: str) -> None:
    """Append an error message to the run log's errors array."""
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE update_run_log
            SET errors = array_append(errors, %s)
            WHERE id = %s;
        """, (error_msg, run_id))
    conn.commit()


# ---------------------------------------------------------------------------
# NVD API interaction
# ---------------------------------------------------------------------------


def build_api_url(start_index: int, last_mod_start: str, last_mod_end: str) -> str:
    """Build the NVD API URL for a given page and time window."""
    return (
        f"{API_BASE}?lastModStartDate={last_mod_start}"
        f"&lastModEndDate={last_mod_end}"
        f"&resultsPerPage={RESULTS_PER_PAGE}"
        f"&startIndex={start_index}"
    )


def build_request_headers() -> dict:
    """Build HTTP headers, optionally including the API key."""
    headers = {"User-Agent": "nvd_scraper/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def fetch_cve_page_raw(start_index: int, last_mod_start: str, last_mod_end: str) -> dict:
    """
    Perform a single HTTP request to the NVD API.
    Raises on HTTP errors or network issues.
    """
    url = build_api_url(start_index, last_mod_start, last_mod_end)
    headers = build_request_headers()
    req = urllib.request.Request(url, headers=headers)

    with urllib.request.urlopen(req) as response:
        raw = response.read().decode("utf-8")
        data = json.loads(raw)

    # Validate the response has the expected structure
    if not isinstance(data, dict):
        raise ValueError(f"API response is not a JSON object: {type(data)}")
    return data


def fetch_cve_page_with_retry(
    start_index: int,
    last_mod_start: str,
    last_mod_end: str,
    max_retries: int = MAX_RETRIES,
) -> dict:
    """
    Fetch a page of CVEs from the NVD API with exponential backoff retry.
    Returns the parsed JSON response, or None if all retries are exhausted.
    """
    last_exception = None

    for attempt in range(1, max_retries + 1):
        try:
            data = fetch_cve_page_raw(start_index, last_mod_start, last_mod_end)
            logger.debug("Page startIndex=%d fetched successfully (attempt %d).", start_index, attempt)
            return data

        except urllib.error.HTTPError as exc:
            status = exc.code
            reason = exc.reason
            last_exception = exc

            if status == 429:
                # Rate limit – use Retry-After header if available
                retry_after = exc.headers.get("Retry-After")
                wait = int(retry_after) if retry_after and retry_after.isdigit() else 30
                logger.warning(
                    "HTTP 429 (rate limited) for page %d. Waiting %ds before retry %d/%d.",
                    start_index, wait, attempt, max_retries,
                )
                time.sleep(wait)
                continue

            elif status == 403:
                logger.warning(
                    "HTTP 403 (forbidden) for page %d. API key may be invalid. "
                    "Retry %d/%d in %ds.",
                    start_index, attempt, max_retries, BACKOFF_BASE_DELAY,
                )
                # Still retry – could be transient
                time.sleep(BACKOFF_BASE_DELAY)
                continue

            elif 500 <= status < 600:
                # Server error – retry with backoff
                delay = min(BACKOFF_BASE_DELAY * (2 ** (attempt - 1)), BACKOFF_MAX_DELAY)
                logger.warning(
                    "HTTP %d for page %d. Retry %d/%d in %.1fs.",
                    status, start_index, attempt, max_retries, delay,
                )
                time.sleep(delay)
                continue

            else:
                # Non-retryable HTTP error
                logger.error(
                    "HTTP %d for page %d: %s. Not retrying.",
                    status, start_index, reason,
                )
                return None

        except (urllib.error.URLError, OSError) as exc:
            # Network-level errors (timeout, DNS failure, connection reset)
            last_exception = exc
            delay = min(BACKOFF_BASE_DELAY * (2 ** (attempt - 1)), BACKOFF_MAX_DELAY)
            logger.warning(
                "Network error for page %d: %s. Retry %d/%d in %.1fs.",
                start_index, exc, attempt, max_retries, delay,
            )
            time.sleep(delay)
            continue

        except (json.JSONDecodeError, ValueError) as exc:
            # Response parsing error
            last_exception = exc
            delay = min(BACKOFF_BASE_DELAY * (2 ** (attempt - 1)), BACKOFF_MAX_DELAY)
            logger.warning(
                "Parse error for page %d: %s. Retry %d/%d in %.1fs.",
                start_index, exc, attempt, max_retries, delay,
            )
            time.sleep(delay)
            continue

        except Exception as exc:
            # Unexpected errors – log and retry
            last_exception = exc
            delay = min(BACKOFF_BASE_DELAY * (2 ** (attempt - 1)), BACKOFF_MAX_DELAY)
            logger.warning(
                "Unexpected error for page %d: %s. Retry %d/%d in %.1fs.",
                start_index, exc, attempt, max_retries, delay,
            )
            time.sleep(delay)
            continue

    # All retries exhausted
    logger.error(
        "Failed to fetch page startIndex=%d after %d retries. Last error: %s",
        start_index, max_retries, last_exception,
    )
    return None


# ---------------------------------------------------------------------------
# Data parsing
# ---------------------------------------------------------------------------


def parse_cpe_matches(cve_data: dict) -> list:
    """
    Extract CPE match entries from configurations[].nodes[].cpeMatch[].
    Returns a list of dicts: {cpe, vulnerable, match_criteria_id}.
    """
    structured_cpes = []

    configurations = cve_data.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                if not criteria:
                    continue
                structured_cpes.append({
                    "cpe": criteria,
                    "vulnerable": cpe_match.get("vulnerable"),
                    "match_criteria_id": cpe_match.get("matchCriteriaId", "")
                })

    return structured_cpes


def parse_cve_entries(vulnerabilities: list) -> list:
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

        # Extract CPE match structure (configurations[].nodes[].cpeMatch[])
        structured_cpes = parse_cpe_matches(cve_data)

        results.append((cve_id, cve_data, structured_affected, structured_cpes))

    return results


# ---------------------------------------------------------------------------
# Database upsert
# ---------------------------------------------------------------------------


def upsert_cve(conn, cve_id: str, cve_data: dict, affected_entries: list, cpe_entries: list) -> None:
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

        # 4. Delete old CPE data for this CVE
        cur.execute("DELETE FROM cve_cpes WHERE cve_id = %s;", (cve_id,))

        # 5. Insert new CPE matches
        for cpe_entry in cpe_entries:
            cur.execute("""
                INSERT INTO cve_cpes (cve_id, cpe, vulnerable, match_criteria_id)
                VALUES (%s, %s, %s, %s);
            """, (
                cve_id,
                cpe_entry["cpe"],
                cpe_entry["vulnerable"],
                cpe_entry["match_criteria_id"]
            ))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point for the incremental update script."""
    run_start = datetime.now(timezone.utc)
    setup_logging()
    register_signal_handlers()

    logger.info("=" * 60)
    logger.info("NVD incremental update STARTED at %s", run_start.isoformat())
    logger.info("=" * 60)

    # -----------------------------------------------------------------------
    # Connect to database
    # -----------------------------------------------------------------------
    try:
        conn = psycopg2.connect(
            host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS
        )
        conn.autocommit = False
        logger.info("Connected to database %s on %s", DB_NAME, DB_HOST)
    except psycopg2.OperationalError as exc:
        logger.critical("Cannot connect to database: %s", exc)
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Initialize schema
    # -----------------------------------------------------------------------
    try:
        init_db(conn)
        logger.info("Database schema initialized/verified.")
    except Exception as exc:
        logger.critical("Failed to initialize database schema: %s", exc)
        conn.close()
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Create run log entry
    # -----------------------------------------------------------------------
    try:
        run_id = create_run_log(conn)
        logger.info("Run log created (ID=%d).", run_id)
    except Exception as exc:
        logger.critical("Failed to create run log entry: %s", exc)
        conn.close()
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Determine time window
    # -----------------------------------------------------------------------
    last_run = get_last_run(conn)
    now = datetime.now(timezone.utc)

    if last_run:
        start_date = last_run  # Pick up from last successful run (no gaps)
        logger.info("Last successful run: %s", last_run.isoformat())
    else:
        start_date = now - timedelta(hours=24)
        logger.info("No previous run found. Fetching last 24 hours.")

    last_mod_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    last_mod_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    logger.info("Time window: %s  →  %s", last_mod_start, last_mod_end)

    # -----------------------------------------------------------------------
    # Paginated fetch & upsert
    # -----------------------------------------------------------------------
    counters = {
        "total_results": 0,
        "pages_total": 0,
        "pages_succeeded": 0,
        "pages_failed": 0,
        "cves_total": 0,
        "cves_succeeded": 0,
        "cves_failed": 0,
        "cves_skipped": 0,
    }

    start_index = 0
    total_results = None
    page_errors = []

    while not shutdown_requested:
        # Health-check the DB connection before each page
        try:
            conn = ensure_db_connection(conn)
        except psycopg2.OperationalError as exc:
            logger.critical("Cannot recover database connection: %s", exc)
            append_run_error(conn, run_id, f"DB connection lost: {exc}")
            break

        logger.info(
            "Fetching page (startIndex=%d, run_id=%d)...",
            start_index, run_id,
        )

        # Fetch with retry
        data = fetch_cve_page_with_retry(start_index, last_mod_start, last_mod_end)

        if data is None:
            # All retries exhausted for this page
            counters["pages_failed"] += 1
            error_msg = f"Page startIndex={start_index}: failed after {MAX_RETRIES} retries"
            page_errors.append(error_msg)
            logger.error("Page %d FAILED. %s", counters["pages_total"] + 1, error_msg)
            append_run_error(conn, run_id, error_msg)

            # Advance and continue to next page
            start_index += RESULTS_PER_PAGE
            if total_results is not None and start_index >= total_results:
                break
            time.sleep(REQUEST_DELAY)
            continue

        counters["pages_total"] += 1

        # Capture total_results on first successful page
        if total_results is None:
            total_results = data.get("totalResults", 0)
            counters["total_results"] = total_results
            logger.info("Total results announced by API: %d", total_results)

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            logger.info("No more results. Ending pagination.")
            counters["pages_succeeded"] += 1
            break

        # Parse and upsert each CVE
        entries = parse_cve_entries(vulnerabilities)
        page_cve_success = 0
        page_cve_failed = 0
        page_cve_skipped = 0

        for cve_id, cve_data, affected_entries, cpe_entries in entries:
            if shutdown_requested:
                logger.warning("Shutdown requested – stopping CVE processing mid-page.")
                break

            counters["cves_total"] += 1
            try:
                upsert_cve(conn, cve_id, cve_data, affected_entries, cpe_entries)
                page_cve_success += 1
                counters["cves_succeeded"] += 1
            except Exception as exc:
                page_cve_failed += 1
                counters["cves_failed"] += 1
                logger.error("Failed to upsert %s: %s", cve_id, exc)
                error_msg = f"CVE {cve_id}: {exc}"
                append_run_error(conn, run_id, error_msg)
                conn.rollback()
                continue

        # Count skipped (CVEs in the API response that had no ID)
        page_cve_skipped = len(vulnerabilities) - len(entries)
        counters["cves_skipped"] += page_cve_skipped

        # Commit the page batch
        try:
            conn.commit()
            counters["pages_succeeded"] += 1
            logger.info(
                "Page %d/%d done: +%d succeeded, %d failed, %d skipped "
                "(total so far: %d succeeded, %d failed, %d skipped)",
                counters["pages_succeeded"],
                total_results // RESULTS_PER_PAGE + 1 if total_results else "?",
                page_cve_success,
                page_cve_failed,
                page_cve_skipped,
                counters["cves_succeeded"],
                counters["cves_failed"],
                counters["cves_skipped"],
            )
        except Exception as exc:
            logger.error("Failed to commit page %d: %s", start_index, exc)
            append_run_error(conn, run_id, f"Commit failed on page {start_index}: {exc}")
            conn.rollback()
            counters["pages_failed"] += 1
            # Continue to next page despite commit failure

        # Check if there are more pages
        start_index += RESULTS_PER_PAGE
        if total_results is not None and start_index >= total_results:
            logger.info("All pages exhausted (total_results=%d).", total_results)
            break

        # Rate limiting delay between normal requests
        if not shutdown_requested:
            time.sleep(REQUEST_DELAY)

    # -----------------------------------------------------------------------
    # Determine final status
    # -----------------------------------------------------------------------
    run_status = "success"
    if shutdown_requested:
        run_status = "partial"
        logger.warning("Run was interrupted by shutdown signal.")
    elif counters["pages_failed"] > 0 and counters["pages_succeeded"] == 0:
        run_status = "failed"
    elif counters["pages_failed"] > 0:
        run_status = "partial"

    # -----------------------------------------------------------------------
    # Update run log
    # -----------------------------------------------------------------------
    try:
        finalize_run_log(conn, run_id, run_status, **counters)
        logger.info("Run log (ID=%d) finalized with status='%s'.", run_id, run_status)
    except Exception as exc:
        logger.error("Failed to finalize run log: %s", exc)

    # -----------------------------------------------------------------------
    # Update last_run timestamp (only if we had at least some success)
    # -----------------------------------------------------------------------
    if counters["cves_succeeded"] > 0:
        try:
            set_last_run(conn, now)
            logger.info("Last-run timestamp updated to %s.", now.isoformat())
        except Exception as exc:
            logger.error("Failed to update last_run timestamp: %s", exc)
    else:
        logger.warning("No CVEs were successfully processed; last_run NOT updated.")

    # -----------------------------------------------------------------------
    # Close connection
    # -----------------------------------------------------------------------
    try:
        conn.close()
        logger.info("Database connection closed.")
    except Exception as exc:
        logger.warning("Error closing database connection: %s", exc)

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    run_end = datetime.now(timezone.utc)
    duration = run_end - run_start
    next_run = (now + timedelta(days=1)).replace(hour=2, minute=0, second=0, microsecond=0)

    logger.info("")
    logger.info("-" * 60)
    logger.info("UPDATE SUMMARY")
    logger.info("-" * 60)
    logger.info("  Run ID:          %d", run_id)
    logger.info("  Status:          %s", run_status.upper())
    logger.info("  Duration:        %s", _format_duration(duration))
    logger.info("  Time window:     %s  →  %s", last_mod_start, last_mod_end)
    logger.info("  Total results:   %d", counters["total_results"])
    logger.info("  Pages succeeded: %d", counters["pages_succeeded"])
    logger.info("  Pages failed:    %d", counters["pages_failed"])
    logger.info("  CVEs succeeded:  %d", counters["cves_succeeded"])
    logger.info("  CVEs failed:     %d", counters["cves_failed"])
    logger.info("  CVEs skipped:    %d", counters["cves_skipped"])
    if page_errors:
        logger.info("  Page errors:")
        for err in page_errors:
            logger.info("    - %s", err)
    logger.info("  Next scheduled:  %s (UTC)", next_run.isoformat())
    logger.info("-" * 60)
    logger.info("NVD incremental update FINISHED at %s", run_end.isoformat())
    logger.info("=" * 60)

    # Exit with non-zero status if the run was not fully successful
    if run_status == "failed":
        sys.exit(2)
    elif run_status == "partial":
        sys.exit(1)


def _format_duration(delta: timedelta) -> str:
    """Format a timedelta into a human-readable string."""
    total_seconds = int(delta.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts)


if __name__ == "__main__":
    main()