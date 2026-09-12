import logging
import os
from contextlib import contextmanager
from typing import Any, Iterator

import psycopg2
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor
from psycopg2.pool import ThreadedConnectionPool

load_dotenv()
logger = logging.getLogger(__name__)

class DatabaseUnavailableError(RuntimeError):
    """Raised when PostgreSQL cannot be reached."""


class Database:
    """Lazily creates a PostgreSQL connection pool on first use."""

    def __init__(self) -> None:
        self._pool: ThreadedConnectionPool | None = None

    def _config(self) -> dict[str, Any]:
        return {
            "host": os.environ["DB_HOST"],
            "dbname": os.environ["DB_NAME"],
            "user": os.environ["DB_USER"],
            "password": os.environ["DB_PASSWORD"],
            "port": int(os.environ.get("DB_PORT", "5432")),
            "connect_timeout": int(os.environ.get("DB_CONNECT_TIMEOUT", "5")),
        }

    def _get_pool(self) -> ThreadedConnectionPool:
        if self._pool is None:
            try:
                self._pool = ThreadedConnectionPool(
                    int(os.environ.get("DB_POOL_MIN", "1")),
                    int(os.environ.get("DB_POOL_MAX", "5")),
                    **self._config(),
                )
            except (KeyError, ValueError, psycopg2.Error) as exc:
                logger.error("Database connection unavailable: %s", exc)
                raise DatabaseUnavailableError("Database is temporarily unavailable") from exc
        return self._pool

    @contextmanager
    def connection(self) -> Iterator[Any]:
        pool = self._get_pool()
        try:
            connection = pool.getconn()
        except psycopg2.Error as exc:
            raise DatabaseUnavailableError("Database is temporarily unavailable") from exc
        try:
            yield connection
        finally:
            pool.putconn(connection)

    def execute_query(self, query: str, params: tuple[Any, ...] | None = None) -> Any:
        """Compatibility helper used by ingestion code; connections remain lazy."""
        with self.connection() as connection:
            try:
                with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                    cursor.execute(query, params)
                    result = cursor.fetchall() if cursor.description else cursor.rowcount
                connection.commit()
                return result
            except psycopg2.Error:
                connection.rollback()
                raise

    def close(self) -> None:
        if self._pool is not None:
            self._pool.closeall()
            self._pool = None

# Safe to import: no connection is opened until a query is executed.
db = Database()
