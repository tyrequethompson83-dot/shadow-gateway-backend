import os

from sqlalchemy import text

from db import engine

MIGRATIONS_DIR = "migrations"
MIGRATION_TABLE = "applied_migrations"

# Prevent concurrent migration runs across replicas on Postgres.
POSTGRES_MIGRATION_LOCK_KEY = 914263871


def ensure_migration_table() -> None:
    """Create a table to track applied migrations (works in Postgres & SQLite)."""

    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            conn.execute(
                text(f"""
                    CREATE TABLE IF NOT EXISTS {MIGRATION_TABLE} (
                        filename TEXT PRIMARY KEY,
                        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                """)
            )
        else:
            conn.execute(
                text(f"""
                    CREATE TABLE IF NOT EXISTS {MIGRATION_TABLE} (
                        filename TEXT PRIMARY KEY,
                        applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            )


def run_migrations() -> None:
    """Run all SQL files in /migrations that haven't been applied yet."""

    ensure_migration_table()
    files = sorted(f for f in os.listdir(MIGRATIONS_DIR) if f.endswith(".sql"))

    with engine.connect() as conn:
        if engine.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_lock(:key)"), {"key": POSTGRES_MIGRATION_LOCK_KEY})
        try:
            with conn.begin():
                for file in files:
                    applied = conn.execute(
                        text(f"SELECT 1 FROM {MIGRATION_TABLE} WHERE filename = :file"),
                        {"file": file},
                    ).scalar()
                    if applied:
                        continue

                    path = os.path.join(MIGRATIONS_DIR, file)
                    with open(path, "r", encoding="utf-8") as f:
                        sql = f.read()

                    if engine.dialect.name == "postgresql":
                        # Drop SQLite-only PRAGMA lines (rest of file should be Postgres compatible).
                        sql = "\n".join(
                            line
                            for line in sql.splitlines()
                            if not line.strip().upper().startswith("PRAGMA")
                        )

                    if sql.strip():
                        conn.execute(text(sql))

                    conn.execute(
                        text(f"INSERT INTO {MIGRATION_TABLE} (filename) VALUES (:file)"),
                        {"file": file},
                    )
                    print(f"Applied migration: {file}")
        finally:
            if engine.dialect.name == "postgresql":
                try:
                    conn.execute(
                        text("SELECT pg_advisory_unlock(:key)"),
                        {"key": POSTGRES_MIGRATION_LOCK_KEY},
                    )
                except Exception:
                    pass
