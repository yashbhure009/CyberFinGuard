"""
DATABASE SETUP SCRIPT - CyberFinGuard
Run this file once to set up the entire database
"""

import sys
import io
import os
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from dotenv import load_dotenv

# ============================================================
# FIX UNICODE ENCODING FOR WINDOWS
# ============================================================
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================
load_dotenv()

DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_NAME = os.getenv('DB_NAME', 'cyber_risk_db')
DB_USER = os.getenv('DB_USER', 'postgres')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'postgres')
DB_PORT = os.getenv('DB_PORT', '5432')

# ============================================================
# SQL SCHEMA
# ============================================================
CREATE_TABLES_SQL = """
-- 1. ASSETS TABLE
CREATE TABLE IF NOT EXISTS assets (
    asset_id VARCHAR(50) PRIMARY KEY,
    asset_name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    hostname VARCHAR(255),
    application VARCHAR(100),
    business_unit VARCHAR(100),
    owner VARCHAR(100),
    environment VARCHAR(20) CHECK (environment IN ('production', 'staging', 'development', 'testing', 'unknown')),
    internet_exposed BOOLEAN DEFAULT FALSE,
    production_status VARCHAR(20) CHECK (production_status IN ('production', 'non-production', 'unknown')),
    criticality INTEGER CHECK (criticality BETWEEN 1 AND 5),
    data_type VARCHAR(50),
    dependencies TEXT[],
    asset_value DECIMAL(15,2),
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. FINDINGS TABLE
CREATE TABLE IF NOT EXISTS findings (
    finding_id VARCHAR(50) PRIMARY KEY,
    asset_id VARCHAR(50) REFERENCES assets(asset_id) ON DELETE CASCADE,
    source VARCHAR(30) NOT NULL,
    cve_id VARCHAR(20),
    cvss_score DECIMAL(3,1),
    epss_score DECIMAL(5,4),
    cisa_kev BOOLEAN DEFAULT FALSE,
    exploit_available BOOLEAN DEFAULT FALSE,
    exploit_type VARCHAR(20),
    mitre_technique VARCHAR(20),
    title TEXT,
    description TEXT,
    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    raw_data JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. ASSET CONTROLS TABLE
CREATE TABLE IF NOT EXISTS asset_controls (
    asset_id VARCHAR(50) PRIMARY KEY REFERENCES assets(asset_id) ON DELETE CASCADE,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    patching_status VARCHAR(20) CHECK (patching_status IN ('patched', 'unpatched', 'partial', 'unknown')),
    waf_enabled BOOLEAN DEFAULT FALSE,
    edr_enabled BOOLEAN DEFAULT FALSE,
    firewall_enabled BOOLEAN DEFAULT FALSE,
    encryption_enabled BOOLEAN DEFAULT FALSE,
    backup_exists BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. RISK SCORES TABLE
CREATE TABLE IF NOT EXISTS risk_scores (
    risk_id VARCHAR(50) PRIMARY KEY,
    asset_id VARCHAR(50) REFERENCES assets(asset_id) ON DELETE CASCADE,
    finding_id VARCHAR(50) REFERENCES findings(finding_id) ON DELETE CASCADE,
    sle DECIMAL(15,2),
    aro DECIMAL(5,4),
    ale DECIMAL(15,2),
    likelihood_score DECIMAL(5,4),
    impact_score DECIMAL(5,4),
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. INVESTMENT RECOMMENDATIONS TABLE
CREATE TABLE IF NOT EXISTS investment_recommendations (
    recommendation_id VARCHAR(50) PRIMARY KEY,
    asset_id VARCHAR(50) REFERENCES assets(asset_id) ON DELETE CASCADE,
    control_name VARCHAR(100),
    investment_cost DECIMAL(15,2),
    risk_reduction DECIMAL(5,4),
    roi DECIMAL(5,4),
    priority INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 6. KEYCLOAK IAM TABLES
CREATE TABLE IF NOT EXISTS iam_users (
    user_id VARCHAR(100) PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    email VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    enabled BOOLEAN DEFAULT FALSE,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    last_seen_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS iam_roles (
    role_id VARCHAR(100) PRIMARY KEY,
    role_name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS iam_groups (
    group_id VARCHAR(100) PRIMARY KEY,
    group_name VARCHAR(255) NOT NULL,
    group_path VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS iam_user_roles (
    user_id VARCHAR(100) REFERENCES iam_users(user_id) ON DELETE CASCADE,
    role_id VARCHAR(100) REFERENCES iam_roles(role_id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS iam_user_groups (
    user_id VARCHAR(100) REFERENCES iam_users(user_id) ON DELETE CASCADE,
    group_id VARCHAR(100) REFERENCES iam_groups(group_id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS iam_authentication_events (
    event_id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(100) REFERENCES iam_users(user_id) ON DELETE SET NULL,
    event_type VARCHAR(100),
    event_time BIGINT,
    event_timestamp TIMESTAMP,
    realm_id VARCHAR(100),
    client_id VARCHAR(255),
    session_id VARCHAR(255),
    ip_address VARCHAR(45),
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 7. INDEXES
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source);
CREATE INDEX IF NOT EXISTS idx_risk_asset ON risk_scores(asset_id);
CREATE INDEX IF NOT EXISTS idx_assets_environment ON assets(environment);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
CREATE INDEX IF NOT EXISTS idx_iam_users_username ON iam_users(username);
CREATE INDEX IF NOT EXISTS idx_iam_users_email ON iam_users(email);
CREATE INDEX IF NOT EXISTS idx_iam_users_mfa ON iam_users(mfa_enabled);
CREATE INDEX IF NOT EXISTS idx_iam_roles_name ON iam_roles(role_name);
CREATE INDEX IF NOT EXISTS idx_iam_groups_name ON iam_groups(group_name);
CREATE INDEX IF NOT EXISTS idx_iam_events_user ON iam_authentication_events(user_id);
CREATE INDEX IF NOT EXISTS idx_iam_events_type ON iam_authentication_events(event_type);
CREATE INDEX IF NOT EXISTS idx_iam_events_time ON iam_authentication_events(event_time);
CREATE INDEX IF NOT EXISTS idx_iam_events_client ON iam_authentication_events(client_id);
"""

# ============================================================
# SAMPLE DATA
# ============================================================
SAMPLE_DATA_SQL = """
-- Sample Assets
INSERT INTO assets (asset_id, asset_name, asset_type, ip_address, hostname, environment, production_status, criticality, asset_value)
VALUES 
    ('AST-001', 'Production Web Server', 'web_server', '192.168.1.10', 'web-01.company.com', 'production', 'production', 4, 20000000),
    ('AST-002', 'Payment Database', 'database', '192.168.1.20', 'db-01.company.com', 'production', 'production', 5, 50000000),
    ('AST-003', 'API Gateway', 'api_server', '192.168.1.30', 'api-01.company.com', 'production', 'production', 4, 25000000),
    ('AST-004', 'Development Server', 'server', '192.168.1.100', 'dev-01.company.com', 'development', 'non-production', 2, 5000000),
    ('AST-005', 'Staging Database', 'database', '192.168.1.50', 'stage-db-01.company.com', 'staging', 'non-production', 3, 10000000)
ON CONFLICT (asset_id) DO NOTHING;

-- Sample Findings
INSERT INTO findings (finding_id, asset_id, source, cve_id, cvss_score, title, description, severity)
VALUES 
    ('FND-001', 'AST-001', 'openvas', 'CVE-2024-1234', 9.1, 'Critical Remote Code Execution', 'Apache Log4j vulnerability affecting web server', 'critical'),
    ('FND-002', 'AST-002', 'openvas', 'CVE-2024-5678', 7.5, 'SQL Injection Vulnerability', 'Database vulnerable to SQL injection attacks', 'high'),
    ('FND-003', 'AST-001', 'wazuh', NULL, NULL, 'Multiple Failed SSH Attempts', '10 failed SSH login attempts from IP 5.5.5.5', 'high'),
    ('FND-004', 'AST-003', 'prowler', NULL, NULL, 'S3 Bucket Public Access', 'S3 bucket has public read access enabled', 'critical'),
    ('FND-005', 'AST-005', 'openvas', 'CVE-2024-9012', 6.5, 'Cross-Site Scripting', 'XSS vulnerability in staging application', 'medium')
ON CONFLICT (finding_id) DO NOTHING;

-- Sample Controls
INSERT INTO asset_controls (asset_id, mfa_enabled, patching_status, waf_enabled, edr_enabled, firewall_enabled, encryption_enabled, backup_exists)
VALUES 
    ('AST-001', true, 'patched', true, true, true, true, true),
    ('AST-002', true, 'unpatched', false, true, true, true, true),
    ('AST-003', false, 'patched', true, false, true, true, true),
    ('AST-004', false, 'partial', false, false, false, false, false),
    ('AST-005', true, 'unpatched', false, true, true, true, false)
ON CONFLICT (asset_id) DO NOTHING;

-- Sample Risk Scores
INSERT INTO risk_scores (risk_id, asset_id, finding_id, sle, aro, ale)
VALUES 
    ('RSK-001', 'AST-001', 'FND-001', 18200000, 0.63, 11466000),
    ('RSK-002', 'AST-002', 'FND-002', 37500000, 0.42, 15750000),
    ('RSK-003', 'AST-001', 'FND-003', 2000000, 0.15, 300000)
ON CONFLICT (risk_id) DO NOTHING;
"""

# ============================================================
# FUNCTIONS
# ============================================================

def test_connection():
    """Test database connection"""
    try:
        conn = psycopg2.connect(
            host=DB_HOST, database=DB_NAME, user=DB_USER,
            password=DB_PASSWORD, port=DB_PORT
        )
        cursor = conn.cursor()
        cursor.execute("SELECT version()")
        version = cursor.fetchone()[0]
        print(f"[OK] Connected to PostgreSQL: {version[:40]}...")
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return False


def create_database():
    """Create database if it doesn't exist"""
    try:
        conn = psycopg2.connect(
            host=DB_HOST, database='postgres', user=DB_USER,
            password=DB_PASSWORD, port=DB_PORT
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        cursor.execute(f"SELECT 1 FROM pg_database WHERE datname = '{DB_NAME}'")
        exists = cursor.fetchone()
        if not exists:
            cursor.execute(f"CREATE DATABASE {DB_NAME}")
            print(f"[OK] Database '{DB_NAME}' created!")
        else:
            print(f"[INFO] Database '{DB_NAME}' already exists.")
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERROR] Failed to create database: {e}")
        return False


def create_tables():
    """Create all tables in the database"""
    try:
        conn = psycopg2.connect(
            host=DB_HOST, database=DB_NAME, user=DB_USER,
            password=DB_PASSWORD, port=DB_PORT
        )
        cursor = conn.cursor()
        cursor.execute(CREATE_TABLES_SQL)
        conn.commit()
        print("[OK] All tables created successfully!")
        
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name
        """)
        tables = cursor.fetchall()
        print("\nTables in database:")
        for table in tables:
            print(f"   - {table[0]}")
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERROR] Failed to create tables: {e}")
        return False


def insert_sample_data():
    """Insert sample data for testing"""
    try:
        conn = psycopg2.connect(
            host=DB_HOST, database=DB_NAME, user=DB_USER,
            password=DB_PASSWORD, port=DB_PORT
        )
        cursor = conn.cursor()
        cursor.execute(SAMPLE_DATA_SQL)
        conn.commit()
        print("[OK] Sample data inserted successfully!")
        
        cursor.execute("SELECT COUNT(*) FROM assets")
        assets_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM findings")
        findings_count = cursor.fetchone()[0]
        print(f"\nData counts:")
        print(f"   - Assets: {assets_count}")
        print(f"   - Findings: {findings_count}")
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERROR] Failed to insert sample data: {e}")
        return False


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("CyberFinGuard - Database Setup")
    print("=" * 60)
    
    print("\n[1/4] Testing PostgreSQL connection...")
    if not test_connection():
        print("\n[ERROR] PostgreSQL is not running!")
        print("Start PostgreSQL service:")
        print("   docker start postgres-risk")
        sys.exit(1)
    
    print("\n[2/4] Creating database...")
    if not create_database():
        sys.exit(1)
    
    print("\n[3/4] Creating tables...")
    if not create_tables():
        sys.exit(1)
    
    print("\n[4/4] Inserting sample data...")
    insert_sample_data()
    
    print("\n" + "=" * 60)
    print("Database setup complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("   1. Run: python main.py")
    print("   2. Check data: SELECT * FROM assets;")