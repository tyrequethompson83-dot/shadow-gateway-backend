import os
from sqlalchemy import text
from db import engine

MIGRATIONS_DIR = "migrations"
MIGRATION_TABLE = "applied_migrations"

def ensure_migration_table():
    """Create a table to track applied migrations (works in Postgres & SQLite)."""
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS {MIGRATION_TABLE} (
                    filename TEXT PRIMARY KEY,
                    applied_at TIMESTAMP NOT NULL DEFAULT NOW()
                )
            """))
        else:  # SQLite
            conn.execute(text(f"""
                CREATE TABLE IF NOT EXISTS {MIGRATION_TABLE} (
                    filename TEXT PRIMARY KEY,
                    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

def run_migrations():
    """Run all SQL files in /migrations that haven’t been applied yet."""
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
            with open(path, "r", encoding="utf-8") as f:
                sql = f.read()

            # Remove SQLite PRAGMA lines if using Postgres
            if engine.dialect.name != "sqlite":
                lines = [line for line in sql.splitlines() if "PRAGMA" not in line.upper()]
                sql = "\n".join(lines)

            # Skip empty files
            if sql.strip():
                conn.execute(text(sql))

            # Mark migration as applied
            conn.execute(
                text(f"INSERT INTO {MIGRATION_TABLE} (filename) VALUES (:file)"),
                {"file": file}
            )
            print(f"Applied migration: {file}")