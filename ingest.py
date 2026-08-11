import os
import json
import glob
import psycopg2
import psycopg2.extras

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "nvd_db")
DB_USER = os.getenv("DB_USER", "nvd_user")
DB_PASS = os.getenv("DB_PASS", "nvd_password")

def init_db(conn):
    with conn.cursor() as cur:
        # Enable pg_trgm extension for fuzzy text matching
        cur.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")

        # Main CVE table (kept for raw JSON)
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
                program_files TEXT[],
                cpes TEXT[]
            );
        """)

        # Migrate existing tables that may lack the cpes column
        cur.execute("ALTER TABLE cve_affected ADD COLUMN IF NOT EXISTS cpes TEXT[];")

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
                match_criteria_id VARCHAR(100),
                version_start_including VARCHAR,
                version_end_excluding VARCHAR,
                version_start_excluding VARCHAR,
                version_end_including VARCHAR,
                config_index INTEGER,
                config_operator VARCHAR,
                node_index INTEGER,
                node_operator VARCHAR,
                node_negate BOOLEAN
            );
        """)

        # Migrate existing tables that may lack the new CPE version range / config context columns
        cur.execute("ALTER TABLE cve_cpes ADD COLUMN IF NOT EXISTS version_start_including VARCHAR;")
        cur.execute("ALTER TABLE cve_cpes ADD COLUMN IF NOT EXISTS version_end_excluding VARCHAR;")
        cur.execute("ALTER TABLE cve_cpes ADD COLUMN IF NOT EXISTS version_start_excluding VARCHAR;")
        cur.execute("ALTER TABLE cve_cpes ADD COLUMN IF NOT EXISTS version_end_including VARCHAR;")
        cur.execute("ALTER TABLE cve_cpes ADD COLUMN IF NOT EXISTS config_index INTEGER;")
        cur.execute("ALTER TABLE cve_cpes ADD COLUMN IF NOT EXISTS config_operator VARCHAR;")
        cur.execute("ALTER TABLE cve_cpes ADD COLUMN IF NOT EXISTS node_index INTEGER;")
        cur.execute("ALTER TABLE cve_cpes ADD COLUMN IF NOT EXISTS node_operator VARCHAR;")
        cur.execute("ALTER TABLE cve_cpes ADD COLUMN IF NOT EXISTS node_negate BOOLEAN;")

        # Weaknesses table (from weaknesses[].description[])
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cve_weaknesses (
                id SERIAL PRIMARY KEY,
                cve_id VARCHAR(50) REFERENCES cve_records(cve_id) ON DELETE CASCADE,
                source VARCHAR,
                type VARCHAR,
                lang VARCHAR,
                value TEXT
            );
        """)

        # Indexes for fast lookups by vendor, product, version
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor ON cve_affected (vendor);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_affected_product ON cve_affected (product);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_versions_version ON cve_versions (version);")

        # Trigram indexes for fuzzy/partial matching on vendor and product
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor_trgm ON cve_affected USING gin (vendor gin_trgm_ops);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_affected_product_trgm ON cve_affected USING gin (product gin_trgm_ops);")

        # Indexes for CPE lookups (trigram index supports LIKE '%...%' queries)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_cpes_cve_id ON cve_cpes (cve_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_cpes_cpe_trgm ON cve_cpes USING gin (cpe gin_trgm_ops);")

        # Indexes for weakness lookups
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_weaknesses_cve_id ON cve_weaknesses (cve_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_weaknesses_value ON cve_weaknesses (value);")

    conn.commit()

def _parse_config_node(
    node,
    config_index,
    config_operator,
    node_index,
    structured_cpes,
    seen_cpes
) -> None:
    """Recursively parse a configuration node (handles nested nodes and cpeMatch)."""
    node_operator = node.get("operator") or "OR"
    node_negate = node.get("negate", False)

    # If this node has nested child nodes, recurse into them with the SAME
    # node_index (they belong to the same logical condition).
    child_nodes = node.get("nodes") or []
    if child_nodes:
        for child_index, child in enumerate(child_nodes):
            _parse_config_node(
                child,
                config_index,
                config_operator,
                node_index,
                structured_cpes,
                seen_cpes
            )
        return

    for cpe_match in node.get("cpeMatch") or []:
        criteria = (cpe_match.get("criteria") or "").strip()
        if not criteria:
            continue

        version_start_including = cpe_match.get("versionStartIncluding", "")
        version_end_excluding = cpe_match.get("versionEndExcluding", "")
        version_start_excluding = cpe_match.get("versionStartExcluding", "")
        version_end_including = cpe_match.get("versionEndIncluding", "")

        # Dedup on criteria + version ranges + configuration context so that
        # the same criteria with different ranges or appearing in different
        # AND groups / nodes are all preserved.
        match_key = (
            criteria,
            version_start_including,
            version_end_excluding,
            version_start_excluding,
            version_end_including,
            config_index,
            config_operator,
            node_index,
            node_operator,
            node_negate
        )
        if match_key not in seen_cpes:
            seen_cpes.add(match_key)
            structured_cpes.append({
                "cpe": criteria,
                "vulnerable": cpe_match.get("vulnerable"),
                "match_criteria_id": cpe_match.get("matchCriteriaId", ""),
                "version_start_including": version_start_including,
                "version_end_excluding": version_end_excluding,
                "version_start_excluding": version_start_excluding,
                "version_end_including": version_end_including,
                "config_index": config_index,
                "config_operator": config_operator,
                "node_index": node_index,
                "node_operator": node_operator,
                "node_negate": node_negate
            })


def parse_cpe_matches(cve_data: dict) -> list:
    structured_cpes = []
    seen_cpes = set()

    # 1. Standard NVD configurations
    configurations = cve_data.get("configurations") or []
    for config_index, config in enumerate(configurations):
        config_operator = config.get("operator") or "OR"
        for node_index, node in enumerate(config.get("nodes") or []):
            _parse_config_node(
                node,
                config_index,
                config_operator,
                node_index,
                structured_cpes,
                seen_cpes
            )

    # 2. Vendor-provided affectedData (e.g. Red Hat)
    affected_list = cve_data.get("affected") or []
    for affected_entry in affected_list:
        affected_data_list = affected_entry.get("affectedData") or []
        for ad in affected_data_list:
            # Safely grab 'cpes', defaulting to [] if key missing OR if value is None
            cpes = ad.get("cpes") or []
            for cpe_str in cpes:
                if isinstance(cpe_str, str) and cpe_str.strip():
                    clean_cpe = cpe_str.strip()
                    # No version range or config context fields are available in
                    # affectedData, so dedup without any range bounds or context.
                    match_key = (clean_cpe, "", "", "", "", None, None, None, None, None)
                    if match_key not in seen_cpes:
                        seen_cpes.add(match_key)
                        structured_cpes.append({
                            "cpe": clean_cpe,
                            "vulnerable": ad.get("vulnerable"),
                            "match_criteria_id": None,
                            "version_start_including": "",
                            "version_end_excluding": "",
                            "version_start_excluding": "",
                            "version_end_including": "",
                            "config_index": None,
                            "config_operator": None,
                            "node_index": None,
                            "node_operator": None,
                            "node_negate": None
                        })

    return structured_cpes

def parse_weaknesses(cve_data: dict) -> list:
    """Extract weakness entries from weaknesses[].description[]."""
    structured_weaknesses = []
    seen_weaknesses = set()

    weaknesses = cve_data.get("weaknesses") or []
    for weakness in weaknesses:
        source = weakness.get("source", "")
        wtype = weakness.get("type", "")
        for desc in weakness.get("description") or []:
            lang = desc.get("lang", "")
            value = (desc.get("value", "") or "").strip()
            if not value:
                continue
            match_key = (source, wtype, lang, value)
            if match_key not in seen_weaknesses:
                seen_weaknesses.add(match_key)
                structured_weaknesses.append({
                    "source": source,
                    "type": wtype,
                    "lang": lang,
                    "value": value
                })

    return structured_weaknesses

def parse_single_cve(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)

        cve_id = cve_data.get("id")
        if not cve_id:
            # fallback for older format
            cve_id = cve_data.get("cve", {}).get("id")
        if not cve_id:
            return None

        # Extract affected structure (FKIE-CAD format)
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
                program_files = ad.get("programFiles", [])   # list of strings
                cpes = ad.get("cpes") or []                  # list of CPE strings

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
                    "cpes": cpes,
                    "versions": versions
                })

        # Extract CPE match structure (configurations[].nodes[].cpeMatch[])
        structured_cpes = parse_cpe_matches(cve_data)

        # Extract weakness structure (weaknesses[].description[])
        structured_weaknesses = parse_weaknesses(cve_data)

        return (cve_id, cve_data, structured_affected, structured_cpes, structured_weaknesses)

    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
        return None

def main():
    conn = psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS)
    init_db(conn)

    json_files = glob.glob("/data/**/*.json", recursive=True)
    total_files = len(json_files)
    print(f"Found {total_files} JSON files in /data.")

    processed = 0

    # Use autocommit=False so we can commit per file (or rollback on error)
    conn.autocommit = False

    with conn.cursor() as cur:
        for idx, filepath in enumerate(json_files, 1):
            try:
                result = parse_single_cve(filepath)
                if not result:
                    continue

                cve_id, cve_data, affected_entries, cpe_entries, weakness_entries = result

                # --- 1. Insert/update main CVE record ---
                cur.execute("""
                    INSERT INTO cve_records (cve_id, raw_json)
                    VALUES (%s, %s)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        raw_json = EXCLUDED.raw_json;
                """, (cve_id, psycopg2.extras.Json(cve_data)))

                # --- 2. Delete old affected data for this CVE ---
                cur.execute("DELETE FROM cve_affected WHERE cve_id = %s;", (cve_id,))

                # --- 3. Insert new affected data and versions ---
                for aff in affected_entries:
                    cur.execute("""
                        INSERT INTO cve_affected
                            (cve_id, source, vendor, product, default_status, repo, program_files, cpes)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id;
                    """, (
                        cve_id,
                        aff["source"],
                        aff["vendor"],
                        aff["product"],
                        aff["default_status"],
                        aff["repo"],
                        aff["program_files"],
                        aff["cpes"]   # list will be adapted to TEXT[]
                    ))
                    affected_id = cur.fetchone()[0]

                    # Insert versions for this affected row
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

                # --- 4. Delete old CPE data for this CVE ---
                cur.execute("DELETE FROM cve_cpes WHERE cve_id = %s;", (cve_id,))

                # --- 5. Insert new CPE matches ---
                for cpe_entry in cpe_entries:
                    cur.execute("""
                        INSERT INTO cve_cpes
                            (cve_id, cpe, vulnerable, match_criteria_id,
                             version_start_including, version_end_excluding,
                             version_start_excluding, version_end_including,
                             config_index, config_operator,
                             node_index, node_operator, node_negate)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s,
                                %s, %s, %s, %s, %s);
                    """, (
                        cve_id,
                        cpe_entry["cpe"],
                        cpe_entry["vulnerable"],
                        cpe_entry["match_criteria_id"],
                        cpe_entry["version_start_including"],
                        cpe_entry["version_end_excluding"],
                        cpe_entry["version_start_excluding"],
                        cpe_entry["version_end_including"],
                        cpe_entry["config_index"],
                        cpe_entry["config_operator"],
                        cpe_entry["node_index"],
                        cpe_entry["node_operator"],
                        cpe_entry["node_negate"]
                    ))

                # --- 6. Delete old weakness data for this CVE ---
                cur.execute("DELETE FROM cve_weaknesses WHERE cve_id = %s;", (cve_id,))

                # --- 7. Insert new weaknesses ---
                for weakness_entry in weakness_entries:
                    cur.execute("""
                        INSERT INTO cve_weaknesses (cve_id, source, type, lang, value)
                        VALUES (%s, %s, %s, %s, %s);
                    """, (
                        cve_id,
                        weakness_entry["source"],
                        weakness_entry["type"],
                        weakness_entry["lang"],
                        weakness_entry["value"]
                    ))

                # Commit the transaction for this file
                conn.commit()
                processed += 1

            except Exception as e:
                print(f"Error processing {filepath}: {e}")
                conn.rollback()   # rollback this file's transaction
                continue

            # Progress report every 100 files
            if idx % 100 == 0:
                print(f"Processed {idx} / {total_files} files...")

    print(f"Done! Successfully processed {processed} records.")
    conn.close()

if __name__ == "__main__":
    main()