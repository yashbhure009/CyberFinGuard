"""
Threat Intelligence Analyzer
Generates graphs and statistics from enriched findings
"""

import os
import sys
import json
import logging
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Output folder
OUTPUT_DIR = 'data/analytics'
os.makedirs(OUTPUT_DIR, exist_ok=True)


class ThreatIntelAnalyzer:
    def __init__(self):
        self.output_dir = OUTPUT_DIR

    def fetch_findings(self):
        """Fetch all findings from database"""
        query = """
            SELECT finding_id, source, cve_id, cvss_score, epss_score, cisa_kev, severity, title
            FROM findings
        """
        findings = db.execute_query(query)
        return [dict(f) for f in findings]

    def graph_severity_distribution(self, findings):
        """Graph 1: Severity distribution"""
        df = pd.DataFrame(findings)
        
        if df.empty:
            logger.warning("⚠️ No findings for severity graph")
            return None
        
        severity_counts = df['severity'].value_counts()
        
        # Order
        order = ['critical', 'high', 'medium', 'low', 'info']
        severity_counts = severity_counts.reindex(order).fillna(0)
        
        # Colors
        colors = ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c', '#1976d2']
        
        plt.figure(figsize=(10, 6))
        bars = plt.bar(severity_counts.index, severity_counts.values, color=colors)
        
        # Add values on bars
        for bar, value in zip(bars, severity_counts.values):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    str(int(value)), ha='center', va='bottom', fontweight='bold')
        
        plt.title('Findings by Severity', fontsize=16, fontweight='bold')
        plt.xlabel('Severity Level', fontsize=12)
        plt.ylabel('Number of Findings', fontsize=12)
        plt.grid(axis='y', alpha=0.3)
        
        output_path = os.path.join(self.output_dir, 'severity_distribution.png')
        plt.tight_layout()
        plt.savefig(output_path, dpi=100)
        plt.close()
        
        logger.info(f"✅ Saved: {output_path}")
        return output_path

    def graph_cvss_epss_scatter(self, findings):
        """Graph 2: CVSS vs EPSS scatter plot"""
        df = pd.DataFrame(findings)
        
        # Filter only findings with CVSS and EPSS
        df = df.dropna(subset=['cvss_score', 'epss_score'])
        
        if df.empty:
            logger.warning("⚠️ No enriched findings for scatter plot")
            return None
        
        plt.figure(figsize=(10, 6))
        
        # Color by KEV status
        colors = ['#d32f2f' if kev else '#1976d2' for kev in df['cisa_kev']]
        sizes = [100 if kev else 50 for kev in df['cisa_kev']]
        
        scatter = plt.scatter(
            df['cvss_score'], df['epss_score'],
            c=colors, s=sizes, alpha=0.6, edgecolors='black'
        )
        
        plt.axvline(x=7.0, color='gray', linestyle='--', alpha=0.5, label='High CVSS (7.0)')
        plt.axhline(y=0.5, color='gray', linestyle='--', alpha=0.5, label='High EPSS (0.5)')
        
        plt.title('CVSS vs EPSS: Vulnerability Risk Map', fontsize=16, fontweight='bold')
        plt.xlabel('CVSS Score (Severity)', fontsize=12)
        plt.ylabel('EPSS Score (Exploit Probability)', fontsize=12)
        plt.xlim(0, 10)
        plt.ylim(0, 1)
        plt.grid(alpha=0.3)
        
        # Custom legend
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#d32f2f', label='CISA KEV (Actively Exploited)'),
            Patch(facecolor='#1976d2', label='Not in KEV')
        ]
        plt.legend(handles=legend_elements, loc='upper left')
        
        output_path = os.path.join(self.output_dir, 'cvss_epss_scatter.png')
        plt.tight_layout()
        plt.savefig(output_path, dpi=100)
        plt.close()
        
        logger.info(f"✅ Saved: {output_path}")
        return output_path

    def graph_kev_status(self, findings):
        """Graph 3: CISA KEV status pie chart"""
        df = pd.DataFrame(findings)
        
        if df.empty:
            return None
        
        kev_counts = df['cisa_kev'].value_counts()
        
        labels = []
        sizes = []
        colors = []
        
        if True in kev_counts.index:
            labels.append('CISA KEV (Actively Exploited)')
            sizes.append(kev_counts[True])
            colors.append('#d32f2f')
        
        if False in kev_counts.index:
            labels.append('Not in KEV')
            sizes.append(kev_counts[False])
            colors.append('#1976d2')
        
        plt.figure(figsize=(8, 8))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                startangle=90, textprops={'fontsize': 12})
        plt.title('CISA KEV Status', fontsize=16, fontweight='bold')
        
        output_path = os.path.join(self.output_dir, 'kev_status.png')
        plt.tight_layout()
        plt.savefig(output_path, dpi=100)
        plt.close()
        
        logger.info(f"✅ Saved: {output_path}")
        return output_path

    def graph_findings_by_source(self, findings):
        """Graph 4: Findings by source"""
        df = pd.DataFrame(findings)
        
        if df.empty:
            return None
        
        source_counts = df['source'].value_counts()
        
        colors = ['#1976d2', '#388e3c', '#f57c00', '#7b1fa2', '#d32f2f']
        
        plt.figure(figsize=(10, 6))
        bars = plt.barh(source_counts.index, source_counts.values, color=colors[:len(source_counts)])
        
        for bar, value in zip(bars, source_counts.values):
            plt.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2,
                    str(int(value)), va='center', fontweight='bold')
        
        plt.title('Findings by Source Tool', fontsize=16, fontweight='bold')
        plt.xlabel('Number of Findings', fontsize=12)
        plt.ylabel('Source', fontsize=12)
        plt.grid(axis='x', alpha=0.3)
        
        output_path = os.path.join(self.output_dir, 'findings_by_source.png')
        plt.tight_layout()
        plt.savefig(output_path, dpi=100)
        plt.close()
        
        logger.info(f"✅ Saved: {output_path}")
        return output_path

    def generate_summary_report(self, findings):
        """Generate summary statistics"""
        df = pd.DataFrame(findings)
        
        if df.empty:
            return {}
        
        summary = {
            'total_findings': len(df),
            'by_severity': df['severity'].value_counts().to_dict() if 'severity' in df else {},
            'by_source': df['source'].value_counts().to_dict() if 'source' in df else {},
            'total_cves': df['cve_id'].notna().sum(),
            'kev_count': int(df['cisa_kev'].sum()) if 'cisa_kev' in df else 0,
            'avg_cvss': float(df['cvss_score'].mean()) if 'cvss_score' in df and not df['cvss_score'].isna().all() else None,
            'avg_epss': float(df['epss_score'].mean()) if 'epss_score' in df and not df['epss_score'].isna().all() else None,
        }
        
        # Save as JSON
        report_path = os.path.join(self.output_dir, 'summary_report.json')
        with open(report_path, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        logger.info(f"✅ Saved: {report_path}")
        return summary

    def run(self):
        """Generate all graphs and reports"""
        logger.info("📊 Fetching findings from database...")
        findings = self.fetch_findings()
        logger.info(f"📊 Total findings: {len(findings)}")
        
        if not findings:
            logger.warning("⚠️ No findings to analyze")
            return
        
        # Generate graphs
        logger.info("\n🎨 Generating graphs...")
        self.graph_severity_distribution(findings)
        self.graph_cvss_epss_scatter(findings)
        self.graph_kev_status(findings)
        self.graph_findings_by_source(findings)
        
        # Summary report
        logger.info("\n📝 Generating summary report...")
        summary = self.generate_summary_report(findings)
        
        print("\n" + "=" * 60)
        print("📊 THREAT INTEL SUMMARY")
        print("=" * 60)
        print(f"Total Findings:    {summary.get('total_findings', 0)}")
        print(f"Total CVEs:        {summary.get('total_cves', 0)}")
        print(f"CISA KEV Count:    {summary.get('kev_count', 0)}")
        print(f"Avg CVSS:          {summary.get('avg_cvss', 'N/A')}")
        print(f"Avg EPSS:          {summary.get('avg_epss', 'N/A')}")
        print(f"\nBy Severity:")
        for sev, count in summary.get('by_severity', {}).items():
            print(f"  {sev}: {count}")
        print(f"\nBy Source:")
        for src, count in summary.get('by_source', {}).items():
            print(f"  {src}: {count}")
        print("=" * 60)
        print(f"\n📁 Graphs saved to: {self.output_dir}")


if __name__ == "__main__":
    analyzer = ThreatIntelAnalyzer()
    analyzer.run()