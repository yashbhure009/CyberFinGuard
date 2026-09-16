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

    def get_risk_analysis_context(self, asset_id: str) -> dict[str, Any] | None:
        with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT a.asset_id, a.asset_name, a.asset_type, a.criticality, a.asset_value,
                       a.business_unit, a.internet_exposed,
                       ac.mfa_enabled, ac.patching_status, ac.waf_enabled, ac.edr_enabled,
                       ac.firewall_enabled, ac.encryption_enabled, ac.backup_exists,
                       f.finding_id, f.severity, f.cvss_score, f.epss_score,
                       f.exploit_available, f.cisa_kev
                FROM assets a
                LEFT JOIN asset_controls ac ON ac.asset_id = a.asset_id
                LEFT JOIN findings f ON f.asset_id = a.asset_id
                WHERE a.asset_id = %s
                ORDER BY f.severity, f.finding_id
            """, (asset_id,))
            rows = [dict(row) for row in cursor.fetchall()]
        if not rows:
            return None
        asset = {key: rows[0].get(key) for key in ("asset_id", "asset_name", "asset_type", "criticality", "asset_value", "business_unit", "internet_exposed", "mfa_enabled", "patching_status", "waf_enabled", "edr_enabled", "firewall_enabled", "encryption_enabled", "backup_exists")}
        asset["findings"] = [{key: row.get(key) for key in ("finding_id", "severity", "cvss_score", "epss_score", "exploit_available", "cisa_kev")} for row in rows if row.get("finding_id")]
        return asset

    def get_assistant_context(self) -> dict[str, Any]:
        """Return one compact, explicitly nullable context snapshot for the assistant."""
        with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT severity, COUNT(*) AS count
                FROM findings
                GROUP BY severity
                ORDER BY CASE severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4 ELSE 5 END
            """)
            findings_by_severity = [dict(row) for row in cursor.fetchall()]

            cursor.execute("""
                SELECT finding_id, asset_id, title, severity, cvss_score, epss_score,
                       exploit_available, cisa_kev
                FROM findings
                ORDER BY cvss_score DESC NULLS LAST, epss_score DESC NULLS LAST
                LIMIT 10
            """)
            top_findings = [dict(row) for row in cursor.fetchall()]

            cursor.execute("""
                SELECT asset_id, finding_id, sle, aro, ale, likelihood_score, impact_score
                FROM risk_scores
                ORDER BY ale DESC NULLS LAST
            """)
            risk_scores = [dict(row) for row in cursor.fetchall()]

            cursor.execute("""
                SELECT COUNT(*) AS total_assets,
                       COUNT(*) FILTER (WHERE ac.mfa_enabled) AS mfa_enabled,
                       COUNT(*) FILTER (WHERE ac.waf_enabled) AS waf_enabled,
                       COUNT(*) FILTER (WHERE ac.edr_enabled) AS edr_enabled,
                       COUNT(*) FILTER (WHERE ac.firewall_enabled) AS firewall_enabled,
                       COUNT(*) FILTER (WHERE ac.encryption_enabled) AS encryption_enabled,
                       COUNT(*) FILTER (WHERE ac.backup_exists) AS backup_exists
                FROM assets a
                LEFT JOIN asset_controls ac ON ac.asset_id = a.asset_id
            """)
            control_row = dict(cursor.fetchone() or {})

            cursor.execute("""
                SELECT a.asset_id, a.asset_name, a.asset_type, a.criticality, a.business_unit,
                       COALESCE(ac.mfa_enabled, FALSE) AS mfa_enabled,
                       ac.patching_status,
                       COALESCE((SELECT SUM(rs.ale) FROM risk_scores rs WHERE rs.asset_id = a.asset_id), 0) AS ale,
                       COUNT(f.finding_id) FILTER (WHERE ac.patching_status = 'unpatched') AS unpatched_findings
                FROM assets a
                LEFT JOIN asset_controls ac ON ac.asset_id = a.asset_id
                LEFT JOIN findings f ON f.asset_id = a.asset_id
                GROUP BY a.asset_id, a.asset_name, a.criticality, a.business_unit,
                         ac.mfa_enabled, ac.patching_status
                ORDER BY a.asset_id
            """)
            simulation_assets = [dict(row) for row in cursor.fetchall()]

            cursor.execute("""
                SELECT COALESCE(NULLIF(asset_type, ''), 'unknown') AS key, COUNT(*) AS count
                FROM assets
                GROUP BY COALESCE(NULLIF(asset_type, ''), 'unknown')
                ORDER BY key
            """)
            assets_by_type = [dict(row) for row in cursor.fetchall()]

            cursor.execute("""
                SELECT COALESCE(a.criticality::text, 'unknown') AS key, COUNT(*) AS count
                FROM assets a GROUP BY a.criticality ORDER BY key
            """)
            assets_by_criticality = [dict(row) for row in cursor.fetchall()]

            cursor.execute("""
                SELECT COALESCE(NULLIF(a.business_unit, ''), 'unknown') AS key, COUNT(*) AS count
                FROM assets a GROUP BY COALESCE(NULLIF(a.business_unit, ''), 'unknown') ORDER BY key
            """)
            assets_by_business_unit = [dict(row) for row in cursor.fetchall()]

        total_assets = int(control_row.get("total_assets") or 0)
        controls_coverage = {
            name: (float(control_row.get(name) or 0) / total_assets * 100 if total_assets else None)
            for name in ("mfa_enabled", "waf_enabled", "edr_enabled", "firewall_enabled", "encryption_enabled", "backup_exists")
        }
        populated_ale = [row["ale"] for row in risk_scores if row.get("ale") is not None]
        total_ale = sum(float(value) for value in populated_ale)
        pending_risk_fields = [
            field for field in ("sle", "aro", "ale", "likelihood_score", "impact_score")
            if not any(row.get(field) is not None for row in risk_scores)
        ]
        return {
            "findings_by_severity": findings_by_severity,
            "top_findings": top_findings,
            "risk_scores": risk_scores,
            "controls_coverage_percent": controls_coverage,
            "assets_by_criticality": assets_by_criticality,
            "assets_by_business_unit": assets_by_business_unit,
            "assets_by_type": assets_by_type,
            "iam_setup_status": {
                "registered_iam_assets": sum(int(row["count"]) for row in assets_by_type if row["key"] == "iam"),
                "interpretation": "IAM setup is represented by assets with asset_type='iam'; absence means IAM coverage is not represented in the current dataset, not that every identity control is proven absent.",
            },
            "simulation_assets": simulation_assets,
            "total_ale": total_ale if populated_ale else None,
            "risk_score_status": "Real values are shown where populated; missing risk_scores fields are Pending and must not be estimated.",
            "pending_risk_fields": pending_risk_fields,
        }

    def get_technical_dashboard(self) -> dict[str, Any]:
        with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT 
                    f.finding_id,
                    f.asset_id,
                    COALESCE(a.asset_name, f.asset_id) AS asset_name,
                    COALESCE(a.asset_type, 'service') AS asset_type,
                    a.business_unit,
                    a.criticality,
                    a.asset_value,
                    COALESCE(a.internet_exposed, FALSE) AS internet_exposed,
                    a.environment,
                    a.owner,
                    a.production_status,
                    f.source,
                    f.cve_id,
                    f.cvss_score,
                    f.epss_score,
                    COALESCE(f.cisa_kev, FALSE) AS cisa_kev,
                    COALESCE(f.exploit_available, FALSE) AS exploit_available,
                    f.exploit_type,
                    f.mitre_technique,
                    f.title,
                    COALESCE(f.severity, 'info') AS severity,
                    COALESCE(ac.patching_status, 'unknown') AS patching_status,
                    COALESCE(ac.mfa_enabled, FALSE) AS mfa_enabled,
                    COALESCE(ac.waf_enabled, FALSE) AS waf_enabled,
                    COALESCE(ac.edr_enabled, FALSE) AS edr_enabled,
                    COALESCE(ac.firewall_enabled, FALSE) AS firewall_enabled,
                    COALESCE(ac.encryption_enabled, FALSE) AS encryption_enabled,
                    COALESCE(ac.backup_exists, FALSE) AS backup_exists,
                    rs.likelihood_score,
                    rs.impact_score,
                    rs.ale,
                    f.created_at
                FROM findings f
                LEFT JOIN assets a ON f.asset_id = a.asset_id
                LEFT JOIN asset_controls ac ON f.asset_id = ac.asset_id
                LEFT JOIN risk_scores rs ON f.finding_id = rs.finding_id
                ORDER BY f.created_at DESC
            """)
            findings = [dict(row) for row in cursor.fetchall()]

            cursor.execute("SELECT COUNT(*) AS count FROM assets")
            total_assets = (cursor.fetchone() or {}).get('count', 0)

            cursor.execute("SELECT COUNT(*) AS count FROM asset_controls WHERE patching_status = 'patched'")
            patched_controls = (cursor.fetchone() or {}).get('count', 0)

            cursor.execute("SELECT COUNT(*) AS count FROM asset_controls WHERE mfa_enabled = TRUE AND edr_enabled = TRUE")
            mfa_edr_controls = (cursor.fetchone() or {}).get('count', 0)

        total_findings = len(findings)
        critical_findings = sum(1 for f in findings if f.get('severity') == 'critical')
        unpatched_findings = sum(1 for f in findings if f.get('patching_status') == 'unpatched')
        exploitable_findings = sum(1 for f in findings if f.get('exploit_available') or f.get('cisa_kev'))

        patch_compliance = round((patched_controls / total_assets * 100)) if total_assets > 0 else 0
        mfa_edr_coverage = round((mfa_edr_controls / total_assets * 100)) if total_assets > 0 else 0

        summary = {
            "total_findings": total_findings,
            "critical_findings": critical_findings,
            "unpatched_findings": unpatched_findings,
            "exploitable_findings": exploitable_findings,
            "patch_compliance_percent": patch_compliance,
            "mfa_edr_coverage_percent": mfa_edr_coverage
        }

        return {"summary": summary, "findings": findings}
