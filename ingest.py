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
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cve_records (
                cve_id VARCHAR(50) PRIMARY KEY,
                raw_json JSONB
            );
        """)
    conn.commit()

def parse_single_cve(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)

        cve_id = cve_data.get("id") or cve_data.get("cve", {}).get("id")

        if cve_id:
            return (cve_id, psycopg2.extras.Json(cve_data))
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
    return None

def main():
    conn = psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS)
    init_db(conn)

    json_files = glob.glob("/data/**/*.json", recursive=True)
    print(f"Found {len(json_files)} JSON files in /data.")

    batch = []
    batch_size = 2000
    processed = 0

    query = """
        INSERT INTO cve_records (cve_id, raw_json)
        VALUES (%s, %s)
        ON CONFLICT (cve_id) DO UPDATE SET
            raw_json = EXCLUDED.raw_json;
    """

    with conn.cursor() as cur:
        for filepath in json_files:
            record = parse_single_cve(filepath)
            if record:
                batch.append(record)

            if len(batch) >= batch_size:
                cur.executemany(query, batch)
                conn.commit()
                processed += len(batch)
                print(f"Ingested {processed} / {len(json_files)} files...")
                batch.clear()

        if batch:
            cur.executemany(query, batch)
            conn.commit()
            processed += len(batch)

    print(f"Done! Successfully processed {processed} records.")
    conn.close()

if __name__ == "__main__":
    main()