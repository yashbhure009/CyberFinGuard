import uuid
from typing import Any

from psycopg2.extras import RealDictCursor


class AssetRepository:
    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def create(self, values: dict[str, Any]) -> dict[str, Any]:
        asset_id = f"AST-{uuid.uuid4().hex[:12].upper()}"
        columns = ["asset_id", *values.keys()]
        placeholders = ", ".join(["%s"] * len(columns))
        query = f"""
            INSERT INTO assets ({", ".join(columns)})
            VALUES ({placeholders})
            RETURNING *
        """
        try:
            with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, (asset_id, *values.values()))
                asset = dict(cursor.fetchone())
                cursor.execute(
                    "INSERT INTO asset_controls (asset_id) VALUES (%s) ON CONFLICT DO NOTHING",
                    (asset_id,),
                )
            self.connection.commit()
            return asset
        except Exception:
            self.connection.rollback()
            raise

    def get(self, asset_id: str) -> dict[str, Any] | None:
        with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM assets WHERE asset_id = %s", (asset_id,))
            result = cursor.fetchone()
        return dict(result) if result else None

