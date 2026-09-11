"""
CyberFinGuard - Main Data Ingestion Runner
"""

import sys
import os
import logging
from datetime import datetime

# ============================================================
# CRITICAL: Path setup MUST be before imports
# ============================================================
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ROOT_DIR, 'backend')

sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, BACKEND_DIR)

# Debug: Print paths
print(f"📁 Root: {ROOT_DIR}")
print(f"📁 Backend: {BACKEND_DIR}")
print(f"📁 Backend exists: {os.path.exists(BACKEND_DIR)}")
print(f"📁 Ingestion exists: {os.path.exists(os.path.join(BACKEND_DIR, 'ingestion'))}")

# ============================================================
# Now import
# ============================================================
try:
    from backend.ingestion.zap_ingestor import ZAPIngestor
    print("✅ Import successful: backend.ingestion.zap_ingestor")
except ModuleNotFoundError as e:
    print(f"❌ Import failed: {e}")
    try:
        from CyberFinGuard.backend.ingestion.zap_ingestor import ZAPIngestor
        print("✅ Import successful: ingestion.zap_ingestor")
    except ModuleNotFoundError as e2:
        print(f"❌ Both failed: {e2}")
        sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def run_zap():
    try:
        logger.info("=" * 50)
        logger.info("🕷️ Starting ZAP ingestion...")
        zap = ZAPIngestor()
        result = zap.run()
        logger.info(f"✅ ZAP ingestion complete: {result}")
        return result
    except Exception as e:
        logger.error(f"❌ ZAP ingestion failed: {e}")
        return {"source": "zap", "error": str(e)}


def main():
    print("\n" + "=" * 60)
    print("🚀 CyberFinGuard - Data Ingestion Pipeline")
    print(f"⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")

    results = {}
    results['zap'] = run_zap()

    print("\n" + "=" * 60)
    print("📊 INGESTION SUMMARY")
    print("=" * 60)

    for source, result in results.items():
        print(f"\n🔹 {source.upper()}:")
        if isinstance(result, dict):
            for key, value in result.items():
                print(f"   {key}: {value}")
        else:
            print(f"   {result}")

    print("\n" + "=" * 60)
    print(f"⏰ Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")

    return results


if __name__ == "__main__":
    main()