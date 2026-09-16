-- Drop the view if it already exists so we can re-run this file safely
DROP VIEW IF EXISTS mock_findings_enriched;

CREATE VIEW mock_findings_enriched AS
SELECT
    -- Everything from mock_findings
    m.finding_id,
    m.asset_name,
    m.asset_criticality,
    m.business_value_inr,
    m.cve_id,
    m.cvss_score          AS mock_cvss,
    m.epss_score          AS mock_epss,
    m.cisa_kev            AS mock_kev,
    m.exploit_available,
    m.exploit_type,
    m.threat_actor,
    m.malware,
    m.mitre_technique,
    m.patched,
    m.mfa,
    m.waf,
    m.edr,
    m.incident,

    -- Enrichment from cve_intel (authoritative)
    c.cvss_score          AS intel_cvss,
    c.epss_score          AS intel_epss,
    c.cisa_kev            AS intel_kev,
    c.cwe_id              AS cwe_id,
    c.cvss_vector         AS cvss_vector,
    c.cvss_version        AS cvss_version,
    c.affected_vendor     AS affected_vendor,
    c.affected_product    AS affected_product,
    c.technology          AS technology,
    c.severity            AS intel_severity,
    c.published_year      AS published_year,
    c.description         AS cve_description,

    -- Resolved values: prefer intel where present, fall back to mock
    COALESCE(c.cvss_score, m.cvss_score)              AS resolved_cvss,
    COALESCE(c.epss_score, m.epss_score)              AS resolved_epss,
    COALESCE(c.cisa_kev, m.cisa_kev)                  AS resolved_kev

FROM mock_findings m
LEFT JOIN cve_intel c ON m.cve_id = c.cve_id;
