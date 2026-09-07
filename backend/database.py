import psycopg2
from psycopg2.extras import RealDictCursor
import os
from dotenv import load_dotenv
import logging

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Database:
    def __init__(self):
        self.conn = None
        self.connect()
    
    def connect(self):
        try:
            self.conn = psycopg2.connect(
                host=os.getenv('DB_HOST', 'localhost'),
                database=os.getenv('DB_NAME', 'cyber_risk_db'),
                user=os.getenv('DB_USER', 'postgres'),
                password=os.getenv('DB_PASSWORD', 'postgres'),
                port=os.getenv('DB_PORT', '5432')
            )
            self.conn.autocommit = False
            logger.info("✅ Database connected")
        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            raise
    
    def execute_query(self, query, params=None):
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute(query, params)
            if query.strip().upper().startswith('SELECT'):
                result = cursor.fetchall()
            else:
                self.conn.commit()
                result = cursor.rowcount
            cursor.close()
            return result
        except Exception as e:
            self.conn.rollback()
            cursor.close()
            raise e

db = Database()