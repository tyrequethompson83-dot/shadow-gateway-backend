import os
from sqlalchemy import text
from database import engine

MIGRATIONS_DIR = "migrations"
MIGRATION_TABLE = "applied_migrations"

def ensure_migration_table():
    with engine.begin() as conn:
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS {MIGRATION_TABLE} (
                filename TEXT PRIMARY KEY,
                applied_at TIMESTAMP NOT NULL DEFAULT NOW()
            )
        """))

def run_migrations():
    ensure_migration_table()
    files = sorted(f for f in os.listdir(MIGRATIONS_DIR) if f.endswith(".sql"))

    with engine.begin() as conn:
        for file in files:
            # skip if already applied
            applied = conn.execute(
                text(f"SELECT 1 FROM {MIGRATION_TABLE} WHERE filename = :file"),
                {"file": file}
            ).scalar()
            if applied:
                continue

            path = os.path.join(MIGRATIONS_DIR, file)
            with open(path, "r") as f:
                sql = f.read()
                conn.execute(text(sql))
                conn.execute(
                    text(f"INSERT INTO {MIGRATION_TABLE} (filename) VALUES (:file)"),
                    {"file": file}
                )
                print(f"Applied migration: {file}")