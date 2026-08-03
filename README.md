# NVD Scraper

A tool that downloads **National Vulnerability Database (NVD)** CVE JSON feeds and ingests them into a **PostgreSQL** database for querying and analysis. Includes a daily cron job that keeps the data up-to-date via the NIST NVD API 2.0.

## Overview

This project automates the process of fetching CVE (Common Vulnerabilities and Exposures) data and storing it in a normalized PostgreSQL database. It has two modes:

1. **Initial bulk import** — Uses a sparse Git clone to download CVE JSON feeds from [fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds) (CVE-2025 and CVE-2026 by default), then parses and inserts each record into three related tables.
2. **Daily incremental updates** — A cron service runs `update.py` every day at 2:00 AM, fetching only CVEs modified in the last 24 hours from the NIST NVD API 2.0 using your API key.

### Architecture

```
┌──────────────────────┐     ┌──────────────────┐     ┌─────────────────────────────┐
│  Initial Import      │     │  ingest-tool     │ ──> │  PostgreSQL (db)            │
│  (Git clone)         │     │  (runs once)     │     │  ├─ cve_records (parent)    │
│                      │     │  - init.sh clone  │     │  ├─ cve_affected            │
│                      │     │  - ingest.py      │     │  └─ cve_versions            │
└──────────────────────┘     └──────────────────┘     └─────────────────────────────┘
                                                              ▲
┌──────────────────────┐     ┌──────────────────┐              │
│  Daily Updates       │     │  cron service    │ ─────────────┘
│  (NIST API 2.0)      │     │  (runs daily)    │
│                      │     │  - update.py     │
│  API Key required    │     │  - fetches last  │
│                      │     │    24h of CVEs   │
└──────────────────────┘     └──────────────────┘
```

## Database Schema

The database uses a normalized 3-table design for efficient asset matching by vendor, product, and version.

### `cve_records` — Main CVE table

Stores the raw CVE record and acts as the parent for all related data.

```sql
CREATE TABLE cve_records (
    cve_id VARCHAR(50) PRIMARY KEY,
    raw_json JSONB
);
```

| Column     | Type         | Description                                      |
|------------|-------------|--------------------------------------------------|
| `cve_id`   | `VARCHAR(50)` | Unique CVE identifier (e.g., `CVE-2025-0001`)   |
| `raw_json` | `JSONB`       | Full original CVE record in JSON format          |

### `cve_affected` — Affected products

One row per vendor/product combination per CVE. This is the table you'll query when matching assets by vendor and product.

```sql
CREATE TABLE cve_affected (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) REFERENCES cve_records(cve_id) ON DELETE CASCADE,
    source VARCHAR,
    vendor TEXT,
    product TEXT,
    default_status VARCHAR,
    repo TEXT,
    program_files TEXT[]
);
```

| Column           | Type         | Description                                      |
|-----------------|-------------|--------------------------------------------------|
| `id`            | `SERIAL`     | Auto-increment primary key                       |
| `cve_id`        | `VARCHAR(50)` | Foreign key → `cve_records.cve_id`              |
| `source`        | `VARCHAR`    | Source of the affected entry                     |
| `vendor`        | `TEXT`       | Vendor name (e.g., `apache`, `microsoft`)        |
| `product`       | `TEXT`       | Product name (e.g., `httpd`, `windows_10`)       |
| `default_status`| `VARCHAR`    | Default status (`affected`, `unaffected`, etc.)  |
| `repo`          | `TEXT`       | Repository URL if applicable                     |
| `program_files` | `TEXT[]`     | Array of affected program file paths             |

### `cve_versions` — Version information

One row per version range per affected product. This table enables precise version matching.

```sql
CREATE TABLE cve_versions (
    id SERIAL PRIMARY KEY,
    affected_id INTEGER REFERENCES cve_affected(id) ON DELETE CASCADE,
    version VARCHAR,
    status VARCHAR,
    less_than VARCHAR,
    less_than_or_equal VARCHAR,
    version_type VARCHAR
);
```

| Column               | Type       | Description                                      |
|----------------------|-----------|--------------------------------------------------|
| `id`                 | `SERIAL`   | Auto-increment primary key                       |
| `affected_id`        | `INTEGER`  | Foreign key → `cve_affected.id`                  |
| `version`            | `VARCHAR`  | Specific version string                          |
| `status`             | `VARCHAR`  | `affected`, `unaffected`, or `unknown`           |
| `less_than`          | `VARCHAR`  | Upper bound (exclusive) for version ranges       |
| `less_than_or_equal` | `VARCHAR`  | Upper bound (inclusive) for version ranges       |
| `version_type`       | `VARCHAR`  | Version type (e.g., `semver`, `git`, `custom`)   |

### `cve_cpes` — CPE matches

One row per CPE match entry from `configurations[].nodes[].cpeMatch[]`. This table enables searching by CPE criteria strings (e.g., `cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*`).

```sql
CREATE TABLE cve_cpes (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) REFERENCES cve_records(cve_id) ON DELETE CASCADE,
    cpe TEXT NOT NULL,
    vulnerable BOOLEAN,
    match_criteria_id VARCHAR(100),
    version_start_including VARCHAR,
    version_end_excluding VARCHAR,
    version_start_excluding VARCHAR,
    version_end_including VARCHAR
);
```

| Column                     | Type         | Description                                      |
|----------------------------|-------------|--------------------------------------------------|
| `id`                       | `SERIAL`     | Auto-increment primary key                       |
| `cve_id`                   | `VARCHAR(50)` | Foreign key → `cve_records.cve_id`              |
| `cpe`                      | `TEXT`       | Full CPE criteria string (e.g., `cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*`) |
| `vulnerable`               | `BOOLEAN`    | Whether the CPE match is marked vulnerable       |
| `match_criteria_id`        | `VARCHAR(100)` | NVD match criteria identifier                  |
| `version_start_including`  | `VARCHAR`    | Lowest version affected (inclusive) from `versionStartIncluding` |
| `version_end_excluding`    | `VARCHAR`    | Highest version affected (exclusive) from `versionEndExcluding` |
| `version_start_excluding`  | `VARCHAR`    | Lowest version affected (exclusive) from `versionStartExcluding` |
| `version_end_including`    | `VARCHAR`    | Highest version affected (inclusive) from `versionEndIncluding` |

### `update_tracker` — Update tracking

Tracks the last successful API update to avoid gaps or duplicates.

```sql
CREATE TABLE update_tracker (
    id INT PRIMARY KEY DEFAULT 1,
    last_run TIMESTAMP
);
```

### Indexes

The following indexes are created automatically for fast lookups:

- `idx_cve_affected_vendor` on `cve_affected(vendor)`
- `idx_cve_affected_product` on `cve_affected(product)`
- `idx_cve_versions_version` on `cve_versions(version)`
- `idx_cve_cpes_cve_id` on `cve_cpes(cve_id)`
- `idx_cve_cpes_cpe_trgm` — GIN trigram index on `cve_cpes(cpe)` for fast `LIKE '%...%'` / `ILIKE` searches

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (version 20.10+)
- [Docker Compose](https://docs.docker.com/compose/install/) (version 2.x+)
- At least **5 GB** of free disk space for the CVE data and database.
- A **NIST NVD API key** (free) for daily updates — [request one here](https://nvd.nist.gov/developers/request-an-api-key).

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/faresUnderScore999/nvd_scraper.git
cd nvd_scraper
```

### 2. Set your NVD API key

Create a `.env` file in the project root with your API key:

```bash
echo "NVD_API_KEY="xxxxxxxxxxxxxxx" > .env
```

### 3. Build and run the services

```bash
docker compose up --build
```

This command will:

1. Start a **PostgreSQL 15** container (`db`) with the database `nvd_db`, user `nvd_user`, and password `nvd_password`.
2. Build the **ingest-tool** container, which:
   - Runs `init.sh` — clones the NVD JSON feeds (CVE-2025 and CVE-2026) from [fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds) into the `/data` volume (mapped to `./nvd_files` on your host).
   - Runs `ingest.py` — scans all `.json` files under `/data`, parses them, and inserts/upserts each CVE record into the three normalized tables.
3. Start the **cron** container, which runs `update.py` daily at 2:00 AM to fetch new/modified CVEs from the NIST API.

### 4. Wait for initial ingestion to complete

You will see output similar to:

```
[+] Checking dependencies...
[OK] git is installed.
[OK] bash is installed.
[OK] ping is installed.
[+] Checking internet connection...
[OK] Internet available.
[+] Cloning NVD JSON feeds into /data...
[+] Configuring sparse checkout...
[+] Downloading selected CVE files...
[DONE] NVD CVE files downloaded successfully.
Found 450000 JSON files in /data.
Processed 100 / 450000 files...
Processed 200 / 450000 files...
...
Done! Successfully processed 450000 records.
```

> **Note:** The first run will download ~2–3 GB of CVE data. Subsequent runs will skip the clone step if the data already exists.

### 5. Query the database

Once ingestion is complete, you can connect to the PostgreSQL container and query the data:

```bash
# Connect to the database
docker exec -it nvd-postgres psql -U nvd_user -d nvd_db
```

#### Example queries for asset matching

```sql
-- Find all CVEs affecting a specific vendor
SELECT cve_id, vendor, product
FROM cve_affected
WHERE vendor = 'apache';

-- Find all CVEs affecting a specific product
SELECT cve_id, vendor, product
FROM cve_affected
WHERE product = 'httpd';

-- Find CVEs affecting a specific vendor/product with version details
SELECT
    a.cve_id,
    a.vendor,
    a.product,
    v.version,
    v.status,
    v.less_than,
    v.less_than_or_equal
FROM cve_affected a
JOIN cve_versions v ON v.affected_id = a.id
WHERE a.vendor = 'apache'
  AND a.product = 'httpd';

-- Count CVEs per vendor
SELECT vendor, COUNT(DISTINCT cve_id) AS cve_count
FROM cve_affected
GROUP BY vendor
ORDER BY cve_count DESC
LIMIT 20;

-- Check if a specific version is affected
SELECT a.cve_id, a.vendor, a.product, v.version, v.status
FROM cve_affected a
JOIN cve_versions v ON v.affected_id = a.id
WHERE a.vendor = 'apache'
  AND a.product = 'httpd'
  AND v.version = '2.4.50';

-- Find all CVEs matching a CPE pattern (e.g., Red Hat Enterprise Linux 8.x)
SELECT DISTINCT cve_id, cpe
FROM cve_cpes
WHERE cpe LIKE '%redhat%enterprise_linux:8%'
  AND vulnerable = true;
```

## Daily Updates

The **cron** service automatically fetches new and modified CVEs every day at 2:00 AM using the NIST NVD API 2.0.

### How it works

1. The `update.py` script checks the `update_tracker` table for the last successful run timestamp.
2. It fetches all CVEs modified since that timestamp (paginated, 2000 per request).
3. Each CVE is upserted into the same 3 normalized tables (insert if new, update if modified).
4. On success, the `update_tracker` table is updated with the current timestamp.

### Running the update manually

You can trigger an update at any time:

```bash
docker compose run --rm cron bash -c "python /app/update.py"
```

### Checking update logs

```bash
# Check the run log
psql -h localhost -U nvd_user -d nvd_db -c "SELECT id, status, started_at, finished_at, cves_succeeded, cves_failed, pages_succeeded, pages_failed, errors FROM update_run_log;"

# Check if last_run was updated
psql -h localhost -U nvd_user -d nvd_db -c "SELECT * FROM update_tracker;"



### Environment Variables

| Variable       | Default        | Description                                      |
|---------------|----------------|--------------------------------------------------|
| `DB_HOST`     | `db`           | PostgreSQL hostname                              |
| `DB_NAME`     | `nvd_db`       | PostgreSQL database name                         |
| `DB_USER`     | `nvd_user`     | PostgreSQL user                                  |
| `DB_PASS`     | `nvd_password` | PostgreSQL password                              |
| `NVD_API_KEY` | *(empty)*      | NIST NVD API key for daily updates (set in `.env`) |

### Setting the API key

Create a `.env` file in the project root:

```bash
NVD_API_KEY=your-api-key-here
```

The `.env` file is automatically loaded by Docker Compose. The API key is passed to both the `ingest-tool` and `cron` services.

### Changing CVE Years

To download different CVE years for the initial import, edit the `sparse-checkout set` line in `init.sh`:

```bash
git sparse-checkout set CVE-2025 CVE-2026 CVE-2024   # Add 2024
```

Then rebuild and run:

```bash
docker compose down
rm -rf nvd_files
docker compose up --build
```

## Stopping the Services

```bash
docker compose down
```

To also remove the database volume (deletes all ingested data):

```bash
docker compose down -v
```

## Dependencies

- **Python 3.11** (slim image) with `psycopg2-binary` (PostgreSQL adapter)
- **PostgreSQL 15** (Alpine)
- System tools: `git`, `bash`, `ca-certificates`, `cron`

## License

This project is licensed under the MIT License.