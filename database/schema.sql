-- ============================================================
-- DATABASE SCHEMA FOR CYBER RISK PLATFORM
-- ============================================================

-- 1. ASSETS TABLE (Master asset inventory)
CREATE TABLE assets (
    asset_id VARCHAR(50) PRIMARY KEY,
    asset_name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(50) NOT NULL,  -- database, webserver, etc.
    ip_address INET,
    hostname VARCHAR(255),
    application VARCHAR(100),
    business_unit VARCHAR(100),
    owner VARCHAR(100),
    environment VARCHAR(20) CHECK (environment IN ('production', 'staging', 'development', 'testing')),
    internet_exposed BOOLEAN DEFAULT FALSE,
    production_status VARCHAR(20) CHECK (production_status IN ('production', 'non-production')),
    criticality INTEGER CHECK (criticality BETWEEN 1 AND 5),
    data_type VARCHAR(50),
    dependencies TEXT[],
    asset_value DECIMAL(15,2),  -- Monetary value in INR
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. FINDINGS TABLE (All security findings)
CREATE TABLE findings (
    finding_id VARCHAR(50) PRIMARY KEY,
    asset_id VARCHAR(50) REFERENCES assets(asset_id),
    source VARCHAR(50) NOT NULL,  -- wazuh, openvas, prowler, zap, keycloak
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
    raw_data JSONB,  -- Store original data from source
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. CONTROLS TABLE (Security controls status per asset)
CREATE TABLE asset_controls (
    asset_id VARCHAR(50) REFERENCES assets(asset_id) PRIMARY KEY,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    patching_status VARCHAR(20) CHECK (patching_status IN ('patched', 'unpatched', 'partial')),
    waf_enabled BOOLEAN DEFAULT FALSE,
    edr_enabled BOOLEAN DEFAULT FALSE,
    firewall_enabled BOOLEAN DEFAULT FALSE,
    encryption_enabled BOOLEAN DEFAULT FALSE,
    backup_exists BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. RISK_SCORES TABLE (Calculated risk metrics)
CREATE TABLE risk_scores (
    risk_id VARCHAR(50) PRIMARY KEY,
    asset_id VARCHAR(50) REFERENCES assets(asset_id),
    finding_id VARCHAR(50) REFERENCES findings(finding_id),
    sle DECIMAL(15,2),  -- Single Loss Expectancy
    aro DECIMAL(5,4),   -- Annualized Rate of Occurrence
    ale DECIMAL(15,2),  -- Annualized Loss Expectancy
    likelihood_score DECIMAL(5,4),
    impact_score DECIMAL(5,4),
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. INVESTMENTS TABLE (Optimization recommendations)
CREATE TABLE investment_recommendations (
    recommendation_id VARCHAR(50) PRIMARY KEY,
    asset_id VARCHAR(50) REFERENCES assets(asset_id),
    control_name VARCHAR(100),
    investment_cost DECIMAL(15,2),
    risk_reduction DECIMAL(5,4),
    roi DECIMAL(5,4),
    priority INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================

CREATE INDEX idx_findings_asset ON findings(asset_id);
CREATE INDEX idx_findings_cve ON findings(cve_id);
CREATE INDEX idx_findings_source ON findings(source);
CREATE INDEX idx_risk_asset ON risk_scores(asset_id);